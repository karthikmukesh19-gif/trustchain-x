# Security

Controls that exist in the code today. Planned controls are listed in
`architecture.md`.

## Platform

| Control | Detail |
|---|---|
| Passwords | scrypt (N=2¹⁵, r=8, p=1), random per-user salt, constant-time comparison; 10–128 characters with a letter and a digit |
| Sessions | JWT access tokens (HS256, 60 minutes by default). Production refuses to start without a secret of at least 32 characters |
| Login | Identical response and work for unknown accounts and wrong passwords; rate limited per client address |
| Authorisation | Every project, snapshot, dependency, graph and job query is scoped to the owning user. Another user's project answers 404 |
| Input | Strict Pydantic models, unknown fields rejected, 1 MiB body cap, validation errors never echo the submitted value |
| Transport hardening | CORS allow-list, security headers, API docs disabled in production |
| Audit log | Registration, sign-in, project changes, analysis requests and their outcomes |
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

## Known gaps

- Rate-limit counters are per backend process (Redis-backed counters: Phase 14).
- No token revocation list; tokens are short-lived.
- The browser stores the token in `sessionStorage`; a strict CSP limits the XSS exposure.
- Repository metadata and analysis use one platform-wide `GITHUB_TOKEN`. Use
  a token restricted to public repositories, otherwise private repository
  data would be readable by any user who registers that repository.

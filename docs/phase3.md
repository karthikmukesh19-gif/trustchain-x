# Vulnerability Intelligence and SBOM Foundation (Phase 3)

Phase 3 adds two things on top of the Phase 2 dependency inventory:

1. **Known-vulnerability matching.** The dependency versions found in a
   repository snapshot are compared with advisories published by a
   vulnerability source (OSV in this phase).
2. **A self-verifying SBOM.** A CycloneDX document is generated from the same
   inventory, stored with digests, and can be re-checked at any time.

## What Phase 3 does not do

- **No exploitability prediction.** A match says the installed version number
  lies inside the versions an advisory publishes as affected. It says nothing
  about how likely exploitation is.
- **No code reachability.** Whether the vulnerable code is imported, called or
  reachable is not analysed.
- **No attack-path simulation.**
- **No AI-based or statistical risk prediction**, no risk score and no trust
  score.
- **No detection of unknown vulnerabilities.** Only advisories the source has
  published can be matched. An empty result means "no published advisory
  matched", not "safe".

Research positioning: this phase is the deterministic evidence layer that the
later predictive phases will build on. Everything it reports is either
published by a named source or read from a repository file; nothing is
estimated.

## Pipeline

```text
POST /vulnerabilities/sync      → job vulnerability_sync
    PROVIDER_QUERY   ask the provider which advisories it reports for each (ecosystem, package, version)
    RECORD_INGESTION fetch, normalise and upsert each advisory (raw record kept)
    MATCHING         compare every dependency version with the stored advisories
POST /vulnerabilities/analyze   → job vulnerability_analysis
    MATCHING         the same comparison, using only advisories already stored
POST /sbom/generate             → job sbom_generation
    SBOM_GENERATION  build, canonicalise, digest and store the document
    SBOM_COMPARISON  diff against the project's previous SBOM
```

Jobs use the Phase 2 job system: `queued → running → completed | failed`,
one job per project at a time, executed by the worker. Verification and
on-demand diffs are read-mostly and run inside the request.

## Providers

`backend/app/collectors/providers/` defines `VulnerabilityProvider`
(`supports`, `query`, `fetch`, `normalize`, `health_check`, `describe`). A new
source is a new subclass registered in `build_providers`; the services,
matcher and API do not change.

**OSV** (`osv.py`) uses `POST /v1/querybatch` and `GET /v1/vulns/{id}`.

| Platform ecosystem | OSV ecosystem | Version ordering |
|---|---|---|
| `pypi` | PyPI | PEP 440 |
| `npm` | npm | SemVer |
| `cargo` | crates.io | SemVer |
| `golang` | Go | SemVer (with `v` prefix) |
| `maven` | Maven | restricted: dotted numeric versions with an optional simple qualifier |
| `conan` | ConanCenter | none: only versions an advisory lists explicitly are matched, never ranges |
| `vcpkg`, `cmake`, anything else | — | not queried; counted as unsupported |

The provider URL comes from configuration only (`OSV_API_URL`), must be
`https`, on the default port, without credentials, and its host must be in
`VULNERABILITY_ALLOWED_HOSTS` (default `api.osv.dev`). No request parameter
can supply or change a provider URL. Redirects are not followed, responses are
size-capped, advisory ids are validated against a strict pattern before being
placed in a URL, and retries are bounded (three attempts; `Retry-After` is
honoured up to 30 seconds).

## Normalised advisory record

Stored in `vulnerabilities`, one per `(source, source_id)`:

`source`, `source_id`, `source_url`, `aliases`, `related`, `summary`,
`details`, `severity`, `severity_source`, `cvss[]`, `cwe_ids`, `affected[]`
(`ecosystem`, `package_name`, `versions`, `ranges[].events`,
`fixed_versions`, per-package severity), `references`, `published_at`,
`modified_at`, `withdrawn_at`, `raw` (the record as received), `raw_sha256`,
`ingested_at`, `normalizer_version`.

Rules:

- **Severity** is the label the source publishes (`MODERATE` is shown as
  `MEDIUM`). If there is no label but a CVSS v3 vector, the rating of the
  computed base score is used and `severity_source` says so. Otherwise
  `UNKNOWN`.
- **CVSS**: vectors are stored as published. A v3.x base score is computed
  from the vector with the specification's formula and marked
  `score_origin: computed_from_vector`. v2 and v4 vectors are kept unscored
  (`base_score: null`). No score is ever invented.
- Missing fields are `null`. A record that cannot be normalised is counted as
  a failure, not stored partially.
- Withdrawn advisories are stored but never matched.
- The raw record is stored exactly as received, or not at all (`raw_stored:
  false`) when it is too large or cannot be stored unchanged, so a stored
  record always corresponds to `raw_sha256`.
- An advisory that publishes more versions or ranges than are kept is flagged
  (`versions_truncated`, `ranges_truncated`). A range is never cut short.

## Synchronisation

Ingestion is idempotent: an advisory whose `modified` value and normaliser
version are unchanged is not rewritten. Each run writes a `vulnerability_syncs`
document with counts (`packages_queried`, `records_seen`, `_inserted`,
`_updated`, `_unchanged`, `_failed`) and the errors met.

A sync is `completed` only if every reported advisory was stored. Otherwise:

| Situation | Sync status | Job |
|---|---|---|
| Some advisories could not be fetched or normalised, or the provider reported an id that is not a valid id | `partial` | fails with `SYNC_INCOMPLETE` |
| More advisories than `VULNERABILITY_MAX_RECORDS` | `partial` | fails with `TOO_MANY_ADVISORIES` |
| Timeout, unreachable, rate limited, or five consecutive errors | `failed` | fails with the provider's code (`PROVIDER_TIMEOUT`, `PROVIDER_UNREACHABLE`, `PROVIDER_RATE_LIMITED`, `PROVIDER_ERROR`, `PROVIDER_BAD_RESPONSE`, `PROVIDER_RESPONSE_TOO_LARGE`) |
| Run time above `VULNERABILITY_SYNC_TIMEOUT_SECONDS` | `failed` | `TIMEOUT` |

When a sync does not complete, matching is not run. Advisories that were
fetched are kept, findings from an earlier completed run stay visible and are
labelled as coming from an earlier run, and the page states that the last
synchronisation was incomplete or failed.

## Matching

For every resolved dependency version, the advisories stored for its
`(ecosystem, normalised name)` are evaluated by
`analyzers/vulnerabilities/matching.py`:

- an exact entry in the advisory's `versions` list, or
- OSV range events (`introduced`, `fixed`, `last_affected`, `limit`) compared
  with the ecosystem's version ordering.

| Status | Meaning | Confidence |
|---|---|---|
| `AFFECTED` | The observed version is inside the published affected versions | `HIGH` |
| `UNSUPPORTED` | An advisory names the package but the comparison cannot be made safely (unparseable version, `GIT` ranges, no supported ordering). Never treated as affected | `UNDETERMINED` |
| `CONFLICT` | The provider reports the version but the local evaluation of the published ranges does not confirm it | `LOW` |

Events at the same version keep the order the source lists them in, so
`introduced 2.0, last_affected 2.0` means exactly 2.0 and
`introduced 2.0, fixed 2.0` is empty. When part of an advisory's versions or
ranges was not stored, a version that is not positively matched is
`UNSUPPORTED`, not "not affected".

A version that every published range excludes, and that the provider does
not report, produces no record. Unresolved versions and unsupported ecosystems are counted
in the scan summary and never guessed.

**Confidence describes the version comparison only.** `HIGH` means the
comparison is deterministic; it is not a statement about exploitability,
reachability or risk.

Each match stores its evidence:

- **source** — provider, record id, URL, source modification time, retrieval
  time, SHA-256 of the raw record;
- **observed** — package, installed version, PURL, how the version was
  established (Phase 2 basis), relationship and depth, and up to five
  declarations (`source_file`, `line`, `declaration`, `file_kind`,
  `git_blob_sha`);
- **match** — ordering used, range type, the events and bounds that decided
  it, the affected range as text, whether the provider reported the version,
  and a one-sentence explanation.

Aliases of the same vulnerability (for example a `GHSA-…` and a `PYSEC-…`
record sharing a CVE) are stored as separate matches and share a `group_key`,
used to count distinct vulnerabilities.

Matches are keyed by `(snapshot, dependency, advisory)`. Re-running replaces
them and removes matches that no longer hold.

## SBOM

**Format:** CycloneDX 1.5 JSON, built by `app/sbom/cyclonedx.py` from the
snapshot's dependency inventory and graph.

| Written | Source |
|---|---|
| `metadata.component` | the repository and its commit |
| components: name, group, version, PURL, scope | Phase 2 inventory |
| `hashes` | only integrity values recorded in lockfiles, and only when they are valid hex digests of a known algorithm |
| `dependencies` | Phase 2 graph edges |
| `trustchain:*` properties | ecosystem, relationship and its basis, depth, source files, version status |
| `compositions` | `incomplete` or `unknown` — repository files cannot prove completeness |

Not written because the repository files do not establish them: licences,
suppliers, authors, hashes of packages without a lockfile entry, versions of
unresolved dependencies (the component then has no `version` and a PURL
without one).

**Determinism.** The document is serialised canonically (UTF-8, sorted keys,
no insignificant whitespace). Two digests are stored:

- `document_digest` — SHA-256 of the stored bytes;
- `content_digest` — SHA-256 of the document without `serialNumber`,
  `version` and `metadata.timestamp`, so the same inventory always gives the
  same content digest.

Generating again from an unchanged inventory returns the existing SBOM instead
of storing a duplicate. A new inventory gives a new SBOM version; earlier
versions are kept unchanged.

**Verification** (`POST /sbom/{id}/verify`) checks, and reports each
separately:

1. the stored document can be read;
2. its bytes match `document_digest`;
3. it is in canonical form;
4. its content matches `content_digest`;
5. the per-component records match the document;
6. regenerating from the snapshot's inventory gives the same content.

The SBOM is **integrity-verifiable**: changes to the stored document or to the
inventory it was built from are detected. It is not cryptographically signed,
and the digests are stored in the same database as the document, so someone
who can rewrite the database can rewrite both. Signing is future work. A
failed verification is reported; nothing is repaired or edited.

**Comparison.** Two SBOMs of a project are compared by `app/sbom/diff.py`:
components `ADDED`, `REMOVED`, `CHANGED` (version, or metadata such as scope,
PURL or hashes), changes of ecosystems present (labelled INFERRED),
document-level changes and relationship changes. The diff against the previous
version is stored when an SBOM is generated; any other pair is computed on
request and stored.

## Limits

| Setting | Default | Purpose |
|---|---|---|
| `VULNERABILITY_PROVIDERS` | `osv` | Enabled providers; empty disables vulnerability intelligence |
| `VULNERABILITY_ALLOWED_HOSTS` | `api.osv.dev` | Hosts a provider URL may use |
| `OSV_API_URL` | `https://api.osv.dev` | |
| `VULNERABILITY_TIMEOUT_SECONDS` | 15 | Per request |
| `VULNERABILITY_BATCH_SIZE` | 500 | Packages per batch query |
| `VULNERABILITY_MAX_RECORDS` | 5000 | Advisories fetched per sync |
| `VULNERABILITY_MAX_RECORD_BYTES` | 2 MiB | One advisory |
| `VULNERABILITY_SYNC_TIMEOUT_SECONDS` | 600 | Whole sync |
| `JOB_RATE_LIMIT` / `JOB_RATE_WINDOW_SECONDS` | 30 / 60 | Job starts and provider health checks per client |

## Live provider check

The test suite never contacts the internet. To check the real OSV service:

```bash
docker compose exec backend python -m app.collectors.providers.smoke pypi requests 2.19.1
```

It prints `LIVE PROVIDER VALIDATION`, the provider's health, the advisories
OSV reports for that version, and the local match result for each.

## Known limitations

- One source (OSV). Sources can disagree; a second source and conflict
  reporting between sources are future work.
- Maven version ordering covers common version shapes only; others are
  `UNSUPPORTED`.
- PHP and Ruby dependencies are not extracted (Phase 2 limitation), so they
  are not checked.
- Transitive dependencies are checked only when a lockfile records them.
- Advisory data is fetched when a sync is run; there is no scheduled refresh.
  The page shows when the data was synchronised.
- Rate limits are counted per backend process.

"""Vulnerability intelligence: synchronisation, matching and reads.

Flow for one project snapshot

    resolved dependencies  ->  provider query  ->  advisory records fetched,
    normalised and upserted  ->  local, deterministic version matching  ->
    one match document per (dependency, advisory) with its evidence

What a match means: the advisory's published affected versions include the
version observed in the repository. It is an OBSERVED fact about version
numbers. It is not a statement about exploitability, reachability or risk,
and no score is derived from it.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable

from bson import ObjectId
from pymongo import UpdateOne
from pymongo.database import Database
from pymongo.errors import BulkWriteError

from app.analyzers.vulnerabilities import matching
from app.collectors.providers.base import SEVERITY_RANK, MalformedRecord, PackageQuery, ProviderError, VulnerabilityProvider
from app.models.collections import (
    DEPENDENCIES, PROJECTS, REPOSITORY_SNAPSHOTS, VULNERABILITIES, VULNERABILITY_MATCHES, VULNERABILITY_SOURCES,
    VULNERABILITY_SYNCS,
)
from app.services import jobs
from app.services.analysis import storable
from app.services.jobs import JobContext, JobError

logger = logging.getLogger(__name__)

MATCHER_VERSION = "3.0.0"

AFFECTED = "AFFECTED"          # the observed version is inside the published affected versions
UNSUPPORTED = "UNSUPPORTED"    # could not be decided safely; never treated as affected
CONFLICT = "CONFLICT"          # the provider reports the version, the local evaluation does not confirm it
MATCH_STATUSES = (AFFECTED, UNSUPPORTED, CONFLICT)

CONFIDENCE = {
    AFFECTED: ("HIGH", "Deterministic comparison of the observed version with the versions the source publishes as "
                       "affected. Confidence describes the version match only, not exploitability."),
    UNSUPPORTED: ("UNDETERMINED", "The version comparison could not be carried out safely, so no conclusion is drawn."),
    CONFLICT: ("LOW", "The provider reports this version as affected but the local evaluation of the published ranges "
                      "does not confirm it. Review the advisory."),
}

FATAL_PROVIDER_CODES = {"PROVIDER_TIMEOUT", "PROVIDER_UNREACHABLE", "PROVIDER_RATE_LIMITED"}
MAX_ERRORS_KEPT = 50
MAX_CONSECUTIVE_ERRORS = 5
MAX_DEPENDENCY_EVIDENCE = 5


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _snapshot_for(db: Database, job: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    project = db[PROJECTS].find_one({"_id": job["project_id"]})
    if project is None:
        raise JobError("PROJECT_NOT_FOUND", "The project was deleted before the job started.")
    snapshot = None
    if project.get("latest_snapshot_id") is not None:
        snapshot = db[REPOSITORY_SNAPSHOTS].find_one(
            {"_id": project["latest_snapshot_id"], "project_id": project["_id"], "status": "COMPLETE"}, {"files": 0})
    if snapshot is None:
        raise JobError("NOT_ANALYSED", "Run a dependency analysis first: there is no dependency inventory to check.")
    return project, snapshot


def group_key(source_id: str, aliases: list[str]) -> str:
    """One key for records that describe the same vulnerability (a CVE id when the source gives one)."""
    identifiers = [source_id, *aliases]
    cves = sorted(i for i in identifiers if i.upper().startswith("CVE-"))
    return cves[0] if cves else sorted(identifiers)[0]


# --- synchronisation -----------------------------------------------------------------

def synchronise(context: JobContext, provider: VulnerabilityProvider, project: dict[str, Any], snapshot: dict[str, Any],
                job: dict[str, Any]) -> dict[str, Any]:
    """Fetch and store the advisories a provider reports for the snapshot's resolved dependencies.

    Idempotent: records are upserted on (source, source_id); `first_seen_at` is
    kept, `last_seen_at` moves, and nothing is ever deleted. The returned sync
    document says `completed` only if every reported record was stored.
    """
    db, settings = context.db, context.settings
    started_at = _now()
    dependencies = list(db[DEPENDENCIES].find(
        {"snapshot_id": snapshot["_id"], "project_id": project["_id"]},
        {"ecosystem": 1, "name": 1, "normalized_name": 1, "version": 1}))
    queries = [PackageQuery(d["ecosystem"], d["name"], d["normalized_name"], d["version"]) for d in dependencies if d.get("version")]

    sync_id = ObjectId()
    sync: dict[str, Any] = {
        "_id": sync_id, "provider": provider.name, "project_id": project["_id"], "snapshot_id": snapshot["_id"],
        "job_id": job["_id"], "status": "running", "started_at": started_at, "completed_at": None,
        "dependencies_total": len(dependencies), "packages_queried": 0, "packages_unsupported": 0,
        "packages_unresolved": len(dependencies) - len(queries), "provider_requests": 0,
        "records_seen": 0, "records_inserted": 0, "records_updated": 0, "records_unchanged": 0, "records_failed": 0,
        "errors": [], "error_summary": None, "reported": [],
    }
    db[VULNERABILITY_SYNCS].insert_one(sync)

    def finish(status: str, error_summary: str | None = None) -> dict[str, Any]:
        sync.update(status=status, completed_at=_now(), error_summary=error_summary)
        db[VULNERABILITY_SYNCS].update_one({"_id": sync_id}, {"$set": {k: v for k, v in sync.items() if k != "_id"}})
        db[VULNERABILITY_SOURCES].update_one({"name": provider.name}, {
            "$set": {**provider.describe(), "last_sync_at": sync["completed_at"], "last_sync_status": status,
                     "last_sync_id": sync_id, "updated_at": sync["completed_at"]},
            "$setOnInsert": {"created_at": sync["completed_at"]}}, upsert=True)
        return sync

    try:
        return _synchronise(context, provider, job, sync, sync_id, queries, finish)
    except JobError:
        raise
    except Exception:
        # Whatever went wrong, the record of this run must not be left saying "running".
        if sync["status"] == "running":
            try:
                finish("failed", "The synchronisation stopped because of an internal error.")
            except Exception:  # noqa: BLE001 - the original error is the one worth reporting
                logger.exception("Could not record the failure of synchronisation %s", sync_id)
        raise


def _synchronise(context: JobContext, provider: VulnerabilityProvider, job: dict[str, Any], sync: dict[str, Any],
                 sync_id: ObjectId, queries: list[PackageQuery], finish: Callable[..., dict[str, Any]]) -> dict[str, Any]:
    db, settings = context.db, context.settings
    try:
        jobs.progress(db, job, "PROVIDER_QUERY", f"Asking {provider.display_name} about {len(set(queries))} package version(s)")
        result = provider.query(queries)
    except ProviderError as exc:
        finish("failed", exc.message)
        raise JobError(exc.code, exc.message, exc.retry_at, {"sync_id": sync_id}) from exc

    sync["provider_requests"] = result.requests
    sync["packages_queried"] = len(result.reported)
    sync["packages_unsupported"] = len(result.unsupported)
    sync["reported"] = [
        {"ecosystem": package.ecosystem, "normalized_name": package.normalized_name, "version": package.version, "ids": ids}
        for package, ids in result.reported.items() if ids
    ]
    identifiers = sorted({identifier for ids in result.reported.values() for identifier in ids})
    rejected = sorted(set(result.rejected))
    sync["records_seen"] = len(identifiers) + len(rejected)
    for identifier in rejected:
        _note_failure(sync, identifier, "INVALID_ID", "The provider reported an advisory id that is not a valid id; it was not fetched.")
    over_limit = len(identifiers) > settings.vulnerability_max_records
    if over_limit:
        identifiers = identifiers[:settings.vulnerability_max_records]

    jobs.progress(db, job, "RECORD_INGESTION", f"Fetching {len(identifiers)} advisory record(s)")
    fatal: ProviderError | None = None
    consecutive_errors = 0
    for position, identifier in enumerate(identifiers, start=1):
        try:
            context.check_deadline(settings.vulnerability_sync_timeout_seconds)
        except JobError as exc:
            finish("failed", exc.message)
            raise
        existing = db[VULNERABILITIES].find_one({"source": provider.name, "source_id": identifier},
                                                {"source_modified": 1, "normalizer_version": 1})
        reported_modified = result.modified.get(identifier)
        now = _now()
        current = (existing or {}).get("normalizer_version") == provider.describe().get("normalizer_version")
        if existing and current and reported_modified and existing.get("source_modified") == reported_modified:
            db[VULNERABILITIES].update_one({"_id": existing["_id"]}, {"$set": {"last_seen_at": now}})
            sync["records_unchanged"] += 1
            continue
        try:
            record, raw = provider.fetch(identifier)
            normalized = provider.normalize(record, raw)
            if normalized["source_id"] != identifier:
                raise MalformedRecord("the record's id differs from the id that was requested")
        except ProviderError as exc:
            consecutive_errors += 0 if exc.code == "NOT_FOUND" else 1
            if exc.code in FATAL_PROVIDER_CODES or consecutive_errors >= MAX_CONSECUTIVE_ERRORS:
                # The provider itself is in trouble: stop instead of working through every remaining record.
                fatal = exc
                break
            _note_failure(sync, identifier, exc.code, exc.message)
            continue
        except MalformedRecord as exc:
            _note_failure(sync, identifier, "MALFORMED_RECORD", str(exc))
            continue
        consecutive_errors = 0
        raw_record = normalized.pop("raw", None)
        normalized = storable(normalized, 20000)
        # The raw record is kept exactly as received or not at all, so it always corresponds to raw_sha256.
        keep_raw = raw_record is not None and storable(raw_record, 10**9) == raw_record
        normalized.update(raw=raw_record if keep_raw else None, raw_stored=keep_raw)
        normalized.update(ingested_at=now, normalized_at=now, last_seen_at=now)
        outcome = db[VULNERABILITIES].update_one(
            {"source": provider.name, "source_id": identifier},
            {"$set": normalized, "$setOnInsert": {"first_seen_at": now}}, upsert=True)
        sync["records_inserted" if outcome.upserted_id is not None else "records_updated"] += 1
        if position % 25 == 0:
            jobs.progress(db, job, "RECORD_INGESTION", f"Fetched {position} of {len(identifiers)} advisory record(s)")

    if fatal is not None:
        finish("failed", fatal.message)
        raise JobError(fatal.code, fatal.message, fatal.retry_at, {"sync_id": sync_id})
    if over_limit:
        message = (f"{provider.display_name} reported {sync['records_seen']} advisories; only the first "
                   f"{settings.vulnerability_max_records} were fetched (VULNERABILITY_MAX_RECORDS).")
        finish("partial", message)
        raise JobError("TOO_MANY_ADVISORIES", message, extra={"sync_id": sync_id})
    if sync["records_failed"]:
        message = (f"{sync['records_failed']} of {sync['records_seen']} advisory record(s) could not be stored, so the "
                   "vulnerability data for this project is incomplete. Records that were fetched have been kept.")
        finish("partial", message)
        raise JobError("SYNC_INCOMPLETE", message, extra={"sync_id": sync_id})
    return finish("completed")


def _note_failure(sync: dict[str, Any], identifier: str, code: str, message: str) -> None:
    sync["records_failed"] += 1
    if len(sync["errors"]) < MAX_ERRORS_KEPT:
        sync["errors"].append({"source_id": identifier, "code": code, "message": message[:300]})
    logger.warning("Advisory %s could not be stored: %s (%s)", identifier, message, code)


# --- matching -------------------------------------------------------------------------

def _latest_sync(db: Database, project_id: ObjectId, snapshot_id: ObjectId) -> dict[str, Any] | None:
    return db[VULNERABILITY_SYNCS].find_one({"project_id": project_id, "snapshot_id": snapshot_id},
                                           sort=[("started_at", -1), ("_id", -1)])


def match_snapshot(context: JobContext, project: dict[str, Any], snapshot: dict[str, Any], job: dict[str, Any]) -> dict[str, Any]:
    """Match every resolved dependency of the snapshot against the stored advisories. Uses no network."""
    db = context.db
    jobs.progress(db, job, "MATCHING", "Comparing dependency versions with published affected versions")
    now = _now()
    sync = _latest_sync(db, project["_id"], snapshot["_id"])
    reported: dict[tuple[str, str, str], set[str]] = {}
    if sync is not None:
        for item in sync.get("reported", []):
            reported[(item["ecosystem"], item["normalized_name"], item["version"])] = set(item["ids"])

    dependencies = list(db[DEPENDENCIES].find({"snapshot_id": snapshot["_id"], "project_id": project["_id"]}))
    resolved = [d for d in dependencies if d.get("version")]
    names: dict[str, set[str]] = {}
    for dependency in resolved:
        names.setdefault(dependency["ecosystem"], set()).add(dependency["normalized_name"])

    advisories: dict[tuple[str, str], list[dict[str, Any]]] = {}
    considered: set[ObjectId] = set()
    withdrawn = 0
    for ecosystem, wanted in names.items():
        cursor = db[VULNERABILITIES].find(
            {"affected": {"$elemMatch": {"ecosystem": ecosystem, "package_name": {"$in": sorted(wanted)}}}}, {"raw": 0})
        for advisory in cursor:
            if advisory.get("withdrawn_at") is not None:
                withdrawn += 1
                continue
            considered.add(advisory["_id"])
            for name in {a["package_name"] for a in advisory["affected"] if a.get("ecosystem") == ecosystem} & wanted:
                advisories.setdefault((ecosystem, name), []).append(advisory)

    operations, kept = [], set()
    missing: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    by_severity: Counter[str] = Counter()
    affected_dependencies: set[str] = set()
    groups: set[str] = set()
    for dependency in resolved:
        key = (dependency["ecosystem"], dependency["normalized_name"])
        provider_ids = reported.get((*key, dependency["version"]))
        candidates = advisories.get(key, [])
        known_ids = {a["source_id"] for a in candidates}
        for identifier in sorted((provider_ids or set()) - known_ids):
            missing.append({"dependency": dependency["node_id"], "source_id": identifier})
        for advisory in candidates:
            provider_reported = None if provider_ids is None or advisory["source"] != (sync or {}).get("provider") \
                else advisory["source_id"] in provider_ids
            document = _match_document(project, snapshot, dependency, advisory, provider_reported, job, now)
            if document is None:
                continue
            counts[document["match_status"]] += 1
            if document["match_status"] == AFFECTED:
                by_severity[document["severity"]] += 1
                affected_dependencies.add(dependency["node_id"])
                groups.add(document["group_key"])
            identity = {"snapshot_id": snapshot["_id"], "dependency_node_id": dependency["node_id"], "vulnerability_id": advisory["_id"]}
            kept.add((dependency["node_id"], advisory["_id"]))
            operations.append(UpdateOne(identity, {"$set": document, "$setOnInsert": {"first_matched_at": now}}, upsert=True))

    for start in range(0, len(operations), 500):
        try:
            db[VULNERABILITY_MATCHES].bulk_write(operations[start:start + 500], ordered=False)
        except BulkWriteError as exc:   # a concurrent identical upsert is equally good
            if any(error.get("code") != 11000 for error in exc.details.get("writeErrors", [])):
                raise
    # Matches from an earlier run that no longer hold (advisory withdrawn or corrected) are removed for this snapshot.
    for stale in db[VULNERABILITY_MATCHES].find({"snapshot_id": snapshot["_id"]}, {"dependency_node_id": 1, "vulnerability_id": 1}):
        if (stale["dependency_node_id"], stale["vulnerability_id"]) not in kept:
            db[VULNERABILITY_MATCHES].delete_one({"_id": stale["_id"]})

    unsupported_ecosystems = Counter(d["ecosystem"] for d in resolved if not _ecosystem_covered(context, d["ecosystem"]))
    summary = {
        "snapshot_id": snapshot["_id"], "commit_sha": snapshot["commit_sha"], "matched_at": now, "matcher_version": MATCHER_VERSION,
        "dependencies_total": len(dependencies), "dependencies_checked": len(resolved) - sum(unsupported_ecosystems.values()),
        "dependencies_unresolved": len(dependencies) - len(resolved),
        "dependencies_unsupported_ecosystem": sum(unsupported_ecosystems.values()),
        "unsupported_ecosystems": dict(unsupported_ecosystems),
        "advisories_considered": len(considered), "advisories_withdrawn_skipped": withdrawn,
        "affected_matches": counts[AFFECTED], "affected_dependencies": len(affected_dependencies),
        "distinct_vulnerabilities": len(groups), "unsupported_matches": counts[UNSUPPORTED], "conflict_matches": counts[CONFLICT],
        "by_severity": {level: by_severity.get(level, 0) for level in SEVERITY_RANK},
        "reported_but_not_stored": missing[:100], "reported_but_not_stored_count": len(missing),
        "intelligence": None if sync is None else {
            "sync_id": sync["_id"], "provider": sync["provider"], "status": sync["status"], "completed_at": sync.get("completed_at"),
            "records_seen": sync.get("records_seen"), "records_failed": sync.get("records_failed")},
    }
    db[PROJECTS].update_one({"_id": project["_id"]}, {"$set": {"latest_vulnerability_scan": {**summary, "job_id": job["_id"]},
                                                              "updated_at": now}})
    return summary


def _ecosystem_covered(context: JobContext, ecosystem: str) -> bool:
    return any(provider.supports(ecosystem) for provider in context.providers.values())


def _match_document(project: dict[str, Any], snapshot: dict[str, Any], dependency: dict[str, Any], advisory: dict[str, Any],
                    provider_reported: bool | None, job: dict[str, Any], now: datetime) -> dict[str, Any] | None:
    ecosystem, name, version = dependency["ecosystem"], dependency["normalized_name"], dependency["version"]
    entries = [a for a in advisory["affected"] if a.get("ecosystem") == ecosystem and a.get("package_name") == name]
    evaluations = [matching.evaluate(ecosystem, version, entry) for entry in entries]
    affected = [e for e in evaluations if e.status == matching.AFFECTED]
    undecided = [e for e in evaluations if e.status == matching.UNSUPPORTED]

    if affected:
        # Prefer the range evaluation: it carries the boundaries (and the fixed version) that explain the match.
        chosen = next((e for e in affected if e.evidence_type == matching.VERSION_RANGE), affected[0])
        status = AFFECTED
    elif undecided:
        chosen, status = undecided[0], UNSUPPORTED
    elif provider_reported:
        chosen, status = evaluations[0], CONFLICT
    else:
        return None   # every published range was evaluated and none contains this version

    fixed_versions: list[str] = []
    for entry in entries:
        for value in entry.get("fixed_versions", []):
            if value not in fixed_versions:
                fixed_versions.append(value)
    confidence, confidence_meaning = CONFIDENCE[status]
    explanation = chosen.reason
    if status == CONFLICT:
        explanation = (f"{advisory['source'].upper()} reports {name} {version} as affected by {advisory['source_id']}, but the "
                       f"version is outside the ranges published in the record. {chosen.reason}")
    evidence = {
        "evidence_type": chosen.evidence_type or ("provider_report_only" if provider_reported else "not_evaluable"),
        "source": {
            "provider": advisory["source"], "source_id": advisory["source_id"], "url": advisory.get("source_url"),
            "modified_at": advisory.get("modified_at"), "record_sha256": advisory.get("raw_sha256"),
            "retrieved_at": advisory.get("ingested_at"),
        },
        "observed": {
            "package": dependency["name"], "normalized_name": name, "ecosystem": ecosystem, "installed_version": version,
            "purl": dependency.get("purl"), "version_basis": dependency.get("version_basis"),
            "version_reason": dependency.get("version_reason"), "relationship": dependency.get("relationship"),
            "depth": dependency.get("depth"),
            "declared_in": [
                {"source_file": e.get("source_file"), "line": e.get("line"), "declaration": e.get("declaration"),
                 "file_kind": e.get("file_kind"), "git_blob_sha": e.get("git_blob_sha")}
                for e in dependency.get("evidence", [])[:MAX_DEPENDENCY_EVIDENCE]
            ],
        },
        "match": {
            "comparator": chosen.comparator, "range_type": chosen.range_type, "affected_range": chosen.affected_range,
            "introduced": chosen.introduced, "fixed": chosen.fixed, "last_affected": chosen.last_affected, "limit": chosen.limit,
            "events": chosen.events, "version_listed_by_source": any(e.listed for e in affected),
            "provider_reported": provider_reported, "explanation": explanation,
            "source_range_note": next((e.get("source_range_note") for e in entries if e.get("source_range_note")), None),
        },
    }
    return {
        "project_id": project["_id"], "repository_id": project["repository_id"], "snapshot_id": snapshot["_id"],
        "job_id": job["_id"], "dependency_id": dependency["_id"], "dependency_node_id": dependency["node_id"],
        "vulnerability_id": advisory["_id"], "source": advisory["source"], "source_id": advisory["source_id"],
        "aliases": advisory.get("aliases", []), "group_key": group_key(advisory["source_id"], advisory.get("aliases", [])),
        "summary": advisory.get("summary"),
        "ecosystem": ecosystem, "package_name": dependency["name"], "normalized_name": name, "matched_version": version,
        "relationship": dependency.get("relationship"), "depth": dependency.get("depth"),
        "match_status": status, "classification": "OBSERVED" if status == AFFECTED or provider_reported else None,
        "confidence": confidence, "confidence_meaning": confidence_meaning,
        "severity": advisory.get("severity") or "UNKNOWN", "severity_source": advisory.get("severity_source"),
        "severity_rank": SEVERITY_RANK.get(advisory.get("severity") or "UNKNOWN", 0), "cvss": advisory.get("cvss"),
        "affected_range": chosen.affected_range, "fixed_version": chosen.fixed, "fixed_versions": fixed_versions,
        "evidence": evidence, "matched_at": now, "matcher_version": MATCHER_VERSION,
    }


# --- job handlers ---------------------------------------------------------------------

def _provider(context: JobContext, name: str | None = None) -> VulnerabilityProvider:
    if not context.providers:
        raise JobError("NO_PROVIDER", "No vulnerability provider is enabled (VULNERABILITY_PROVIDERS is empty).")
    if name is None:
        return next(iter(context.providers.values()))
    if name not in context.providers:
        raise JobError("NO_PROVIDER", f"The vulnerability provider {name!r} is not enabled.")
    return context.providers[name]


@jobs.handler(jobs.VULNERABILITY_SYNC)
def run_sync(context: JobContext, job: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    project, snapshot = _snapshot_for(context.db, job)
    provider = _provider(context, job.get("parameters", {}).get("provider"))
    sync = synchronise(context, provider, project, snapshot, job)
    summary = match_snapshot(context, project, snapshot, job)
    message = (f"{provider.display_name} data synchronised; {summary['affected_matches']} match(es) on "
               f"{summary['affected_dependencies']} dependency version(s)")
    return message, {"summary": summary, "sync_id": sync["_id"], "snapshot_id": snapshot["_id"]}


@jobs.handler(jobs.VULNERABILITY_ANALYSIS)
def run_matching(context: JobContext, job: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    project, snapshot = _snapshot_for(context.db, job)
    summary = match_snapshot(context, project, snapshot, job)
    message = f"{summary['affected_matches']} match(es) on {summary['affected_dependencies']} dependency version(s), using stored advisories"
    return message, {"summary": summary, "snapshot_id": snapshot["_id"]}


# --- reads ----------------------------------------------------------------------------

def scan_for(project: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any] | None:
    """The stored scan summary, if it belongs to the snapshot currently served."""
    scan = project.get("latest_vulnerability_scan")
    return scan if scan and scan.get("snapshot_id") == snapshot["_id"] else None


def delete_project_data(db: Database, project_id: ObjectId) -> None:
    """Remove a project's matches and sync history. Advisory records are shared and kept."""
    db[VULNERABILITY_MATCHES].delete_many({"project_id": project_id})
    db[VULNERABILITY_SYNCS].delete_many({"project_id": project_id})

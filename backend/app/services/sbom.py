"""SBOM lifecycle: generation, history, integrity verification and comparison.

Every SBOM is generated from a repository snapshot's dependency inventory and
stored unchanged. Verification is integrity verification: it shows whether the
stored SBOM still equals what was generated and what the snapshot yields
today. It is not a signature and does not make the SBOM tamper-proof; anyone
able to rewrite both the SBOM and the inventory it is checked against could
defeat it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import zlib
from datetime import datetime, timezone
from typing import Any

from bson import ObjectId
from bson.binary import Binary
from pymongo.database import Database
from pymongo.errors import DocumentTooLarge, DuplicateKeyError

from app.models.collections import (
    DEPENDENCIES, DEPENDENCY_GRAPHS, PROJECTS, REPOSITORY_SNAPSHOTS, SBOM_COMPONENTS, SBOM_DIFFERENCES, SBOMS,
    VULNERABILITY_MATCHES,
)
from app.sbom import canonical, cyclonedx
from app.sbom import diff as sbom_diff
from app.services import jobs
from app.services.jobs import JobContext, JobError

logger = logging.getLogger(__name__)

MAX_DOCUMENT_BYTES = 14 * 1024 * 1024   # compressed size that still fits a MongoDB document


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --- building -------------------------------------------------------------------------

def build_document(db: Database, project_id: ObjectId, snapshot: dict[str, Any], generated_at: datetime,
                   generator_version: str = cyclonedx.GENERATOR_VERSION) -> dict[str, Any]:
    """Build the SBOM for a snapshot from the stored dependency inventory and graph."""
    dependencies = list(db[DEPENDENCIES].find({"snapshot_id": snapshot["_id"], "project_id": project_id}))
    graph = db[DEPENDENCY_GRAPHS].find_one({"snapshot_id": snapshot["_id"], "project_id": project_id}, {"edges": 1}) or {}
    return cyclonedx.build(project_id=str(project_id), snapshot=snapshot, dependencies=dependencies,
                           edges=graph.get("edges", []), generated_at=generated_at, generator_version=generator_version)


def _component_rows(sbom_id: ObjectId, project_id: ObjectId, snapshot_id: ObjectId, document: dict[str, Any]) -> list[dict[str, Any]]:
    depends = {entry["ref"]: entry.get("dependsOn", []) for entry in document.get("dependencies", [])}
    rows = []
    for item in document["components"]:
        rows.append({
            "sbom_id": sbom_id, "project_id": project_id, "snapshot_id": snapshot_id, "bom_ref": item["bom-ref"],
            "ecosystem": cyclonedx.component_property(item, "ecosystem"),
            "name": f"{item['group']}{':' if cyclonedx.component_property(item, 'ecosystem') == 'maven' else '/'}{item['name']}"
                    if item.get("group") else item["name"],
            "normalized_name": cyclonedx.component_property(item, "normalized_name"),
            "version": item.get("version"), "purl": item.get("purl"), "scope": item.get("scope"),
            "relationship": cyclonedx.component_property(item, "relationship"),
            "hashes": item.get("hashes", []), "depends_on": depends.get(item["bom-ref"], []),
            "component_digest": canonical.digest(item),
        })
    return rows


def generate(db: Database, project: dict[str, Any], snapshot: dict[str, Any], job_id: ObjectId | None = None) -> tuple[dict[str, Any], bool]:
    """Generate and store the SBOM for a snapshot. Returns (sbom, reused).

    Generating again from an unchanged inventory yields the same content
    digest; the existing SBOM is returned instead of storing a duplicate.
    """
    now = _now()
    document = build_document(db, project["_id"], snapshot, now)
    content = canonical.content_digest(document)
    existing = db[SBOMS].find_one({"project_id": project["_id"], "snapshot_id": snapshot["_id"], "content_digest": content})
    if existing is not None:
        return existing, True

    payload = canonical.canonical_bytes(document)
    compressed = zlib.compress(payload, 6)
    if len(compressed) > MAX_DOCUMENT_BYTES:
        raise JobError("SBOM_TOO_LARGE", "The SBOM is too large to store.")
    previous = db[SBOMS].find_one({"project_id": project["_id"]}, sort=[("version", -1)])
    sbom_id = ObjectId()
    sbom = {
        "_id": sbom_id, "project_id": project["_id"], "repository_id": project["repository_id"],
        "snapshot_id": snapshot["_id"], "commit_sha": snapshot["commit_sha"], "branch": snapshot.get("branch"),
        "job_id": job_id, "version": (previous["version"] + 1) if previous else 1,
        "previous_sbom_id": previous["_id"] if previous else None,
        "format": cyclonedx.FORMAT, "spec_version": cyclonedx.SPEC_VERSION, "media_type": cyclonedx.MEDIA_TYPE,
        "serial_number": document["serialNumber"],
        "generator": {"name": cyclonedx.GENERATOR_NAME, "version": cyclonedx.GENERATOR_VERSION},
        "generated_at": now, "source": "repository snapshot dependency inventory",
        "component_count": len(document["components"]),
        "relationship_count": len(cyclonedx.relationships(document)),
        "unresolved_components": sum(1 for c in document["components"] if "version" not in c),
        "components_with_hashes": sum(1 for c in document["components"] if c.get("hashes")),
        "completeness": document["compositions"][0]["aggregate"],
        "digest_algorithm": canonical.ALGORITHM, "canonicalization": canonical.DESCRIPTION,
        "content_digest": content, "document_digest": hashlib.sha256(payload).hexdigest(),
        "document_size": len(payload), "document_zlib": Binary(compressed), "last_verification": None,
    }
    try:
        db[SBOMS].insert_one(sbom)
    except DuplicateKeyError:   # generated concurrently from the same inventory
        return db[SBOMS].find_one({"project_id": project["_id"], "snapshot_id": snapshot["_id"], "content_digest": content}), True
    rows = _component_rows(sbom_id, project["_id"], snapshot["_id"], document)
    if rows:
        db[SBOM_COMPONENTS].insert_many(rows, ordered=False)
    db[PROJECTS].update_one({"_id": project["_id"]}, {"$set": {"latest_sbom_id": sbom_id, "updated_at": now}})
    return sbom, False


def load_document(sbom: dict[str, Any]) -> tuple[dict[str, Any] | None, bytes | None]:
    """Decompress and parse the stored document. Returns (None, None) if it cannot be read."""
    try:
        payload = zlib.decompress(bytes(sbom["document_zlib"]))
        document = json.loads(payload)
    except (KeyError, TypeError, ValueError, zlib.error):
        return None, None
    return (document, payload) if isinstance(document, dict) else (None, payload)


# --- job handler ----------------------------------------------------------------------

@jobs.handler(jobs.SBOM_GENERATION)
def run_generation(context: JobContext, job: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    db = context.db
    project = db[PROJECTS].find_one({"_id": job["project_id"]})
    if project is None:
        raise JobError("PROJECT_NOT_FOUND", "The project was deleted before the job started.")
    snapshot = None
    if project.get("latest_snapshot_id") is not None:
        snapshot = db[REPOSITORY_SNAPSHOTS].find_one(
            {"_id": project["latest_snapshot_id"], "project_id": project["_id"], "status": "COMPLETE"}, {"files": 0})
    if snapshot is None:
        raise JobError("NOT_ANALYSED", "Run a dependency analysis first: an SBOM is generated from the dependency inventory.")

    jobs.progress(db, job, "SBOM_GENERATION", f"Generating a {cyclonedx.FORMAT} {cyclonedx.SPEC_VERSION} SBOM for commit {snapshot['commit_sha'][:10]}")
    sbom, reused = generate(db, project, snapshot, job["_id"])

    difference = None
    if not reused and sbom.get("previous_sbom_id") is not None:
        jobs.progress(db, job, "SBOM_COMPARISON", "Comparing with the previous SBOM")
        previous = db[SBOMS].find_one({"_id": sbom["previous_sbom_id"], "project_id": project["_id"]})
        if previous is not None:
            difference = difference_between(db, project["_id"], previous, sbom)
    summary = {
        "sbom_id": sbom["_id"], "version": sbom["version"], "format": sbom["format"], "spec_version": sbom["spec_version"],
        "component_count": sbom["component_count"], "relationship_count": sbom["relationship_count"],
        "content_digest": sbom["content_digest"], "reused": reused,
        "changes_from_previous": difference["summary"] if difference else None,
    }
    message = ("The dependency inventory is unchanged; the existing SBOM was kept" if reused
               else f"SBOM version {sbom['version']} generated with {sbom['component_count']} component(s)")
    return message, {"summary": summary, "sbom_id": sbom["_id"], "snapshot_id": snapshot["_id"]}


# --- verification ---------------------------------------------------------------------

def verify(db: Database, project: dict[str, Any], sbom: dict[str, Any]) -> dict[str, Any]:
    """Check a stored SBOM's integrity. Returns {"valid", "checks", ...} and records the outcome on the SBOM."""
    checks: list[dict[str, Any]] = []

    def check(name: str, ok: bool, detail: str, **extra: Any) -> bool:
        checks.append({"name": name, "ok": ok, "detail": detail, **extra})
        return ok

    document, payload = load_document(sbom)
    if document is None or payload is None:
        check("stored_document_readable", False, "The stored SBOM document cannot be read.")
    else:
        actual = hashlib.sha256(payload).hexdigest()
        check("stored_document_digest", actual == sbom.get("document_digest"),
              "The stored document matches the digest recorded when it was generated."
              if actual == sbom.get("document_digest") else "The stored document does not match its recorded digest.",
              expected=sbom.get("document_digest"), actual=actual)
        canonical_now = canonical.canonical_bytes(document)
        check("canonical_form", canonical_now == payload,
              "The stored document is in canonical form." if canonical_now == payload
              else "The stored document is not in canonical form.")
        content = canonical.content_digest(document)
        check("content_digest", content == sbom.get("content_digest"),
              "The content digest matches the one recorded at generation." if content == sbom.get("content_digest")
              else "The content does not match the recorded content digest.",
              expected=sbom.get("content_digest"), actual=content)

        rows = {r["bom_ref"]: r["component_digest"] for r in db[SBOM_COMPONENTS].find(
            {"sbom_id": sbom["_id"]}, {"bom_ref": 1, "component_digest": 1})}
        components = document.get("components")
        well_formed = isinstance(components, list) and all(
            isinstance(c, dict) and isinstance(c.get("bom-ref"), str) for c in components)
        if not well_formed:
            check("component_records", False, "The stored document's component list is not in the expected form.", differing=[])
        else:
            in_document = {c["bom-ref"]: canonical.digest(c) for c in components}
            differing = sorted(ref for ref in set(rows) | set(in_document) if rows.get(ref) != in_document.get(ref))
            check("component_records", not differing,
                  "Every stored component record matches the document." if not differing
                  else f"{len(differing)} component record(s) differ from the document.", differing=differing[:50])

    snapshot = db[REPOSITORY_SNAPSHOTS].find_one(
        {"_id": sbom["snapshot_id"], "project_id": project["_id"], "status": "COMPLETE"}, {"files": 0})
    regenerated_difference = None
    if snapshot is None:
        check("regeneration", False, "The snapshot this SBOM was generated from is no longer available, so it cannot be regenerated.")
    else:
        regenerated = build_document(db, project["_id"], snapshot, sbom["generated_at"], sbom["generator"]["version"])
        regenerated_content = canonical.content_digest(regenerated)
        same = regenerated_content == sbom.get("content_digest")
        if not same and document is not None:
            try:
                regenerated_difference = sbom_diff.compare(regenerated, document)
            except Exception:  # noqa: BLE001 - a document too damaged to compare is still reported as different
                logger.warning("SBOM %s could not be compared with its regeneration", sbom["_id"], exc_info=True)
        check("regeneration", same,
              "Regenerating the SBOM from the snapshot's dependency inventory gives the same content."
              if same else "Regenerating the SBOM from the snapshot's dependency inventory gives different content.",
              expected=sbom.get("content_digest"), actual=regenerated_content)

    result = {
        "valid": all(c["ok"] for c in checks), "verified_at": _now(), "checks": checks,
        "digest_algorithm": canonical.ALGORITHM, "canonicalization": canonical.DESCRIPTION,
        "difference_from_regenerated": None if regenerated_difference is None else {
            "summary": regenerated_difference["summary"], "items": regenerated_difference["items"][:100],
            "relationships_added": regenerated_difference["relationships_added"][:100],
            "relationships_removed": regenerated_difference["relationships_removed"][:100],
            "document_changes": regenerated_difference["document_changes"][:50]},
        "meaning": "Integrity-verifiable: the SBOM is checked against its recorded digests and against a fresh "
                   "generation from the snapshot. It is not cryptographically signed.",
    }
    db[SBOMS].update_one({"_id": sbom["_id"]}, {"$set": {"last_verification": {
        "valid": result["valid"], "verified_at": result["verified_at"],
        "failed_checks": [c["name"] for c in checks if not c["ok"]]}}})
    return result


# --- comparison -----------------------------------------------------------------------

def difference_between(db: Database, project_id: ObjectId, base: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    """The stored difference from `base` to `target`, computing and storing it on first use."""
    existing = db[SBOM_DIFFERENCES].find_one({"project_id": project_id, "base_sbom_id": base["_id"], "target_sbom_id": target["_id"]})
    if existing is not None:
        return existing
    base_document, _ = load_document(base)
    target_document, _ = load_document(target)
    if base_document is None or target_document is None:
        raise JobError("SBOM_UNREADABLE", "One of the SBOM documents cannot be read. Verify it to see what is wrong.")
    try:
        comparison = sbom_diff.compare(base_document, target_document)
    except Exception:  # noqa: BLE001 - a stored document that is valid JSON but not a usable SBOM
        logger.warning("SBOMs %s and %s could not be compared", base["_id"], target["_id"], exc_info=True)
        raise JobError("SBOM_UNREADABLE", "One of the SBOM documents cannot be read. Verify it to see what is wrong.") from None
    record = {
        "project_id": project_id, "base_sbom_id": base["_id"], "target_sbom_id": target["_id"],
        "base_snapshot_id": base["snapshot_id"], "target_snapshot_id": target["snapshot_id"],
        "base_commit_sha": base.get("commit_sha"), "target_commit_sha": target.get("commit_sha"),
        "base_version": base.get("version"), "target_version": target.get("version"),
        "base_content_digest": base.get("content_digest"), "target_content_digest": target.get("content_digest"),
        "created_at": _now(), **comparison,
    }
    try:
        record["_id"] = db[SBOM_DIFFERENCES].insert_one(record).inserted_id
    except DuplicateKeyError:
        return db[SBOM_DIFFERENCES].find_one({"project_id": project_id, "base_sbom_id": base["_id"], "target_sbom_id": target["_id"]})
    except DocumentTooLarge:
        # Too large to keep; it is still returned and will simply be computed again next time.
        record.pop("_id", None)
        logger.warning("The difference between SBOMs %s and %s is too large to store", base["_id"], target["_id"])
    return record


# --- reads ----------------------------------------------------------------------------

HIDDEN_FIELDS = {"document_zlib": 0}


def get(db: Database, project_id: ObjectId, sbom_id: str, with_document: bool = False) -> dict[str, Any] | None:
    if not ObjectId.is_valid(sbom_id):
        return None
    return db[SBOMS].find_one({"_id": ObjectId(sbom_id), "project_id": project_id}, None if with_document else HIDDEN_FIELDS)


def history(db: Database, project_id: ObjectId, limit: int = 100) -> list[dict[str, Any]]:
    return list(db[SBOMS].find({"project_id": project_id}, HIDDEN_FIELDS).sort([("version", -1)]).limit(limit))


def vulnerability_linkage(db: Database, sbom: dict[str, Any]) -> dict[str, Any]:
    """Vulnerability matches currently stored for the SBOM's snapshot, keyed by component reference."""
    by_component: dict[str, list[dict[str, Any]]] = {}
    cursor = db[VULNERABILITY_MATCHES].find(
        {"project_id": sbom["project_id"], "snapshot_id": sbom["snapshot_id"], "match_status": "AFFECTED"},
        {"dependency_node_id": 1, "source_id": 1, "severity": 1, "fixed_version": 1, "matched_at": 1})
    latest = None
    for match in cursor:
        by_component.setdefault(match["dependency_node_id"], []).append({
            "match_id": match["_id"], "source_id": match["source_id"], "severity": match["severity"],
            "fixed_version": match.get("fixed_version")})
        if latest is None or match["matched_at"] > latest:
            latest = match["matched_at"]
    return {"by_component": by_component, "components_with_matches": len(by_component),
            "affected_matches": sum(len(v) for v in by_component.values()), "latest_match_at": latest}


def delete_project_data(db: Database, project_id: ObjectId) -> None:
    db[SBOM_DIFFERENCES].delete_many({"project_id": project_id})
    db[SBOM_COMPONENTS].delete_many({"project_id": project_id})
    db[SBOMS].delete_many({"project_id": project_id})

"""The project's security dataset: building versions from stored analysis results, validating them, and reads.

A dataset version holds one record per dependency of a snapshot. Records are
written once and never edited; a change in the underlying results produces a
new version linked to the previous one by a hash chain. Validation always
reads the records back from storage, so it checks what is stored rather than
what was just computed.
"""

from __future__ import annotations

from typing import Any

from bson import ObjectId
from pymongo.database import Database

from app.analyzers.dataset import MODEL_VERSION, integrity, validate
from app.analyzers.graph.risk_propagation import reachability_state
from app.models.collections import (
    ATTACK_PATHS, DATASET_QUALITY, DATASET_RECORDS, DATASETS, DEPENDENCIES, DEPENDENCY_FRAGILITY, GRAPH_RISK_ANALYSIS, PREDICTIONS, PROJECTS,
    REACHABILITY_ANALYSES, REPOSITORY_SNAPSHOTS,
)
from app.services import attack_paths, intelligence, jobs, runs
from app.services.analysis import storable
from app.services.jobs import JobContext, JobError

SCHEMA_VERSION = "1"
ROW_COLLECTIONS = (DATASET_RECORDS, DATASET_QUALITY, DATASETS)
RECORD_FIELDS = {"_id": 0, "record_id": 1, "identity": 1, "features": 1, "labels": 1, "provenance": 1, "record_hash": 1}
_BATCH = 1000


def build_records(db: Database, project: dict[str, Any], snapshot: dict[str, Any], limit: int) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], bool]:
    """One record per dependency from what the analysis layers stored. Returns (records, layers that contributed, truncated).

    A field whose layer has not been analysed is None: missing, not zero.
    """
    project_id, snapshot_id = project["_id"], snapshot["_id"]
    scan = project.get("latest_vulnerability_scan") or {}
    scanned = scan.get("snapshot_id") == snapshot_id
    layers: dict[str, dict[str, Any]] = {"inventory": {
        "collection": DEPENDENCIES, "reference": snapshot_id, "collected_at": snapshot.get("collected_at"), "basis": "OBSERVED",
        "model_version": snapshot.get("analyzer_version")}}
    vulnerabilities = intelligence.vulnerability_summaries(db, project_id, snapshot_id) if scanned else {}
    if scanned:
        layers["vulnerabilities"] = {"collection": "vulnerability_matches", "reference": scan.get("job_id"), "collected_at": scan.get("matched_at"),
                                     "basis": "OBSERVED", "model_version": scan.get("matcher_version")}
    reach, reach_analysed, _modules, _reference = intelligence.reachability_summaries(db, project_id, snapshot_id)
    if reach_analysed:
        analysis = db[REACHABILITY_ANALYSES].find_one({"project_id": project_id, "snapshot_id": snapshot_id, "state": "COMPLETE"},
                                                     sort=[("completed_at", -1)]) or {}
        layers["reachability"] = {"collection": "code_reachability", "reference": analysis.get("_id"), "collected_at": analysis.get("completed_at"),
                                  "basis": "DERIVED", "model_version": analysis.get("analyzer_version")}

    def rows(layer: str, collection: str, fields: dict[str, int], basis: str, version_key: str) -> dict[str, dict[str, Any]]:
        record = intelligence.latest_analysis(db, project, layer)
        if record is None:
            return {}
        layers[layer] = {"collection": collection, "reference": record["_id"], "collected_at": record.get("created_at"), "basis": basis,
                         "model_version": (record.get("model_versions") or {}).get(version_key)}
        return {row["node_id"]: row for row in db[collection].find({"analysis_id": record["_id"]}, {"_id": 0, "node_id": 1, **fields})}

    fragility = rows("fragility", DEPENDENCY_FRAGILITY, {"fragility_score": 1}, "DERIVED", "fragility")
    graph_risk = rows("graph_risk", GRAPH_RISK_ANALYSIS, {"graph_risk": 1}, "DERIVED", "graph_risk")
    predictive = rows("predictive", PREDICTIONS, {"score": 1, "level": 1}, "PREDICTED", "predictive")
    paths: dict[str, dict[str, Any]] = {}
    path_run = attack_paths.latest(db, project)
    if path_run is not None:
        layers["attack_paths"] = {"collection": ATTACK_PATHS, "reference": path_run["_id"], "collected_at": path_run.get("created_at"),
                                  "basis": "DERIVED", "model_version": path_run.get("model_version")}
        for row in db[ATTACK_PATHS].find({"analysis_id": path_run["_id"]}, {"_id": 0, "target.node_id": 1, "score": 1}):
            entry = paths.setdefault(row["target"]["node_id"], {"count": 0, "max": 0.0})
            entry["count"] += 1
            entry["max"] = max(entry["max"], row["score"])

    records = []
    cursor = db[DEPENDENCIES].find(
        {"snapshot_id": snapshot_id, "project_id": project_id},
        {"node_id": 1, "name": 1, "normalized_name": 1, "ecosystem": 1, "version": 1, "version_status": 1, "relationship": 1, "depth": 1,
         "dependents_count": 1, "dependency_count": 1, "purl": 1}).sort("node_id", 1).limit(limit + 1)
    truncated = False
    for position, dependency in enumerate(cursor):
        if position >= limit:
            truncated = True
            break
        node_id = dependency["node_id"]
        found = vulnerabilities.get(node_id) or {}
        count = found.get("distinct", 0) if scanned else None
        state = None
        if scanned and reach_analysed:
            state = reachability_state(reach.get(node_id), True) if count else "NOT_APPLICABLE"
        reachable = None
        if scanned and reach_analysed:
            reachable = True if state == "REACHABLE" else False if state in ("NOT_APPLICABLE", "NOT_CONFIRMED_REACHABLE") else None
        path = paths.get(node_id)
        features = {
            "relationship": dependency.get("relationship"), "depth": dependency.get("depth"), "dependents": dependency.get("dependents_count"),
            "dependencies": dependency.get("dependency_count"), "version_resolved": dependency.get("version_status") == "RESOLVED",
            "vulnerability_count": count, "max_severity": None if not scanned else found.get("max_severity", "UNKNOWN") if count else "NOT_APPLICABLE",
            "reachability_state": state, "fragility_score": (fragility.get(node_id) or {}).get("fragility_score"),
            "graph_risk": (graph_risk.get(node_id) or {}).get("graph_risk"), "predictive_risk": (predictive.get(node_id) or {}).get("score"),
            "attack_path_count": None if path_run is None else (path or {}).get("count", 0),
            "max_attack_path_score": None if path_run is None else (path or {}).get("max", 0.0),
        }
        labels = {"vulnerable": bool(count) if scanned else None, "reachable_vulnerability": reachable,
                  "risk_level": (predictive.get(node_id) or {}).get("level")}
        record = {
            "record_id": node_id,
            "identity": {"ecosystem": dependency.get("ecosystem"), "name": dependency.get("normalized_name") or dependency.get("name"),
                         "version": dependency.get("version"), "purl": dependency.get("purl")},
            "features": features, "labels": labels,
            "provenance": [{"layer": layer, **entry} for layer, entry in layers.items()],
        }
        record = storable(record, 500)
        record["record_hash"] = integrity.record_hash(record)
        records.append(record)
    return records, layers, truncated


def chain_intact(db: Database, project_id: ObjectId) -> bool | None:
    """Whether every version's chain hash follows from the version before it. None when there are no versions."""
    versions = list(db[DATASETS].find({"project_id": project_id}, {"version": 1, "dataset_hash": 1, "chain_hash": 1, "previous_dataset_id": 1})
                    .sort("version", 1))
    if not versions:
        return None
    previous: dict[str, Any] | None = None
    for position, version in enumerate(versions, start=1):
        expected_previous = previous["_id"] if previous else None
        if version["version"] != position or version.get("previous_dataset_id") != expected_previous:
            return False
        if version.get("chain_hash") != integrity.chain_hash(previous["chain_hash"] if previous else None, version["dataset_hash"]):
            return False
        previous = version
    return True


def stored_records(db: Database, dataset_id: ObjectId) -> list[dict[str, Any]]:
    return list(db[DATASET_RECORDS].find({"dataset_id": dataset_id}, RECORD_FIELDS).sort("record_id", 1))


def _changes(db: Database, previous: dict[str, Any] | None, records: list[dict[str, Any]]) -> dict[str, Any] | None:
    if previous is None:
        return None
    if previous.get("records_pruned"):
        return {"comparable": False, "reason": "The records of the previous version are no longer kept."}
    before = {doc["record_id"]: doc["record_hash"] for doc in db[DATASET_RECORDS].find({"dataset_id": previous["_id"]}, {"record_id": 1, "record_hash": 1})}
    after = {record["record_id"]: record["record_hash"] for record in records}
    added, removed = sorted(set(after) - set(before)), sorted(set(before) - set(after))
    changed = sorted(key for key in set(after) & set(before) if after[key] != before[key])
    return {"comparable": True, "added": len(added), "removed": len(removed), "changed": len(changed),
            "unchanged": len(after) - len(added) - len(changed), "added_examples": added[:20], "removed_examples": removed[:20],
            "changed_examples": changed[:20]}


def _run(context: JobContext, job: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    db, settings = context.db, context.settings
    project = db[PROJECTS].find_one({"_id": job["project_id"]})
    if project is None:
        raise JobError("PROJECT_NOT_FOUND", "The project was deleted before the job started.")
    snapshot = db[REPOSITORY_SNAPSHOTS].find_one(
        {"_id": project.get("latest_snapshot_id"), "project_id": project["_id"], "status": "COMPLETE"}, {"files": 0}) \
        if project.get("latest_snapshot_id") else None
    if snapshot is None:
        raise JobError("NOT_ANALYSED", "Run a dependency analysis first: the dataset is built from its results.")
    now = runs.now()

    jobs.progress(db, job, "RECORD_BUILDING", "Building records from the stored analysis results")
    records, layers, truncated = build_records(db, project, snapshot, settings.dataset_max_records)
    context.check_deadline(settings.intelligence_timeout_seconds)
    content_hash = integrity.dataset_hash(records)
    latest_version = db[DATASETS].find_one({"project_id": project["_id"]}, sort=[("version", -1)])
    unchanged = latest_version is not None and latest_version["dataset_hash"] == content_hash \
        and latest_version.get("snapshot_id") == snapshot["_id"] and not latest_version.get("records_pruned")
    if unchanged:
        dataset = latest_version
    else:
        dataset = {
            "_id": ObjectId(), "project_id": project["_id"], "repository_id": project["repository_id"], "owner_id": project["owner_id"],
            "name": f"{project.get('name') or 'project'} dependency security dataset",
            "version": (latest_version["version"] + 1) if latest_version else 1, "schema_version": SCHEMA_VERSION,
            "snapshot_id": snapshot["_id"], "commit_sha": snapshot.get("commit_sha"), "branch": snapshot.get("branch"),
            "record_count": len(records), "truncated": truncated, "hash_algorithm": integrity.ALGORITHM,
            "canonical_form": integrity.CANONICAL_FORM, "dataset_hash": content_hash,
            "previous_dataset_id": latest_version["_id"] if latest_version else None,
            "previous_dataset_hash": latest_version["dataset_hash"] if latest_version else None,
            "chain_hash": integrity.chain_hash(latest_version["chain_hash"] if latest_version else None, content_hash),
            "sources": storable([{"layer": layer, **entry} for layer, entry in layers.items()]),
            "changes": _changes(db, latest_version, records), "created_at": now, "job_id": job["_id"], "records_pruned": False,
            "latest_quality": None, "validations": 0,
        }
        scope = {"dataset_id": dataset["_id"], "project_id": project["_id"]}
        try:
            for start in range(0, len(records), _BATCH):
                db[DATASET_RECORDS].insert_many([{**scope, **record} for record in records[start:start + _BATCH]], ordered=False)
            db[DATASETS].insert_one(dataset)
        except Exception:
            db[DATASET_RECORDS].delete_many({"dataset_id": dataset["_id"]})
            db[DATASETS].delete_one({"_id": dataset["_id"]})
            raise

    jobs.progress(db, job, "VALIDATION", f"Validating version {dataset['version']} ({dataset['record_count']} records) as stored")
    result = validate(stored_records(db, dataset["_id"]), expected_dataset_hash=dataset["dataset_hash"], expected_count=dataset["record_count"],
                      layers_available=layers, now=runs.now(), snapshot_committed_at=snapshot.get("committed_at"),
                      chain_intact=chain_intact(db, project["_id"]), truncated=bool(dataset.get("truncated")))
    quality_id = ObjectId()
    validated_at = runs.now()
    db[DATASET_QUALITY].insert_one(storable({"_id": quality_id, "dataset_id": dataset["_id"], "project_id": project["_id"],
                                             "dataset_version": dataset["version"], "job_id": job["_id"], "created_at": validated_at, **result}, 1000))
    latest_quality = {"quality_id": quality_id, "status": result["status"], "quality_score": result["quality_score"],
                      "confidence": result["confidence"], "validated_at": validated_at}
    db[DATASETS].update_one({"_id": dataset["_id"]}, {"$set": {"latest_quality": latest_quality}, "$inc": {"validations": 1}})
    _prune(db, project["_id"], settings.intelligence_history_limit)
    summary = {"dataset_id": dataset["_id"], "version": dataset["version"], "new_version": not unchanged, "records": dataset["record_count"],
               "status": result["status"], "quality_score": result["quality_score"], "confidence": result["confidence"],
               "warnings": len(result["warnings"]), "dataset_hash": dataset["dataset_hash"]}
    what = f"Version {dataset['version']} created" if not unchanged else f"Version {dataset['version']} is unchanged and was validated again"
    score = "no score" if result["quality_score"] is None else f"quality {result['quality_score']}"
    return f"{what}: {dataset['record_count']} record(s), {result['status']}, {score}", {"summary": summary, "snapshot_id": snapshot["_id"]}


def _prune(db: Database, project_id: ObjectId, keep: int) -> None:
    """Keep the records of the newest versions. Older versions keep their description and hashes, so the chain stays verifiable."""
    old = [doc["_id"] for doc in db[DATASETS].find({"project_id": project_id, "records_pruned": {"$ne": True}}, {"_id": 1})
           .sort("version", -1).skip(keep)]
    if old:
        db[DATASET_RECORDS].delete_many({"dataset_id": {"$in": old}})
        db[DATASETS].update_many({"_id": {"$in": old}}, {"$set": {"records_pruned": True}})


jobs.handler(jobs.DATASET_VALIDATION)(_run)


def latest(db: Database, project: dict[str, Any]) -> dict[str, Any] | None:
    """The newest dataset version of the project's latest snapshot."""
    if project.get("latest_snapshot_id") is None:
        return None
    return db[DATASETS].find_one({"project_id": project["_id"], "snapshot_id": project["latest_snapshot_id"]}, sort=[("version", -1)])


def get(db: Database, project_id: ObjectId, dataset_id: str) -> dict[str, Any] | None:
    if not ObjectId.is_valid(dataset_id):
        return None
    return db[DATASETS].find_one({"_id": ObjectId(dataset_id), "project_id": project_id})


def verify_now(db: Database, dataset: dict[str, Any]) -> dict[str, Any]:
    """Recompute the hashes of a version's stored records right now."""
    if dataset.get("records_pruned"):
        return {"status": "NOT_AVAILABLE", "reason": "The records of this version are no longer kept; only its hashes are."}
    check = integrity.verify(stored_records(db, dataset["_id"]), dataset["dataset_hash"], dataset["record_count"])
    check["chain_intact"] = chain_intact(db, dataset["project_id"])
    if check["chain_intact"] is False:
        check["status"] = "MISMATCH"
    return check


def delete_project_data(db: Database, project_id: ObjectId) -> None:
    for collection in ROW_COLLECTIONS:
        db[collection].delete_many({"project_id": project_id})


__all__ = ["MODEL_VERSION", "build_records", "chain_intact", "delete_project_data", "get", "latest", "stored_records", "verify_now"]

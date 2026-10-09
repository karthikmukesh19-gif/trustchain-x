"""Stored trust scores: writing a result, reading the current one, the history and comparisons."""

from __future__ import annotations

from typing import Any

from bson import ObjectId
from pymongo.database import Database

from app.models.collections import TRUST_SCORES
from app.services.analysis import storable

SERIES_FIELDS = {"created_at": 1, "status": 1, "trust_score": 1, "risk_score": 1, "confidence": 1, "coverage": 1, "risk_low": 1, "risk_high": 1,
                 "snapshot_id": 1, "commit_sha": 1, "model_version": 1, "band": 1, "component_scores": 1, "unknown_components": 1}


def store(db: Database, document: dict[str, Any]) -> dict[str, Any]:
    document = storable(document, 2000)
    db[TRUST_SCORES].insert_one(document)
    return document


def latest(db: Database, project: dict[str, Any]) -> dict[str, Any] | None:
    """The newest score of the project's latest snapshot. A score of an earlier snapshot is history, not the current state."""
    if project.get("latest_snapshot_id") is None:
        return None
    return db[TRUST_SCORES].find_one({"project_id": project["_id"], "snapshot_id": project["latest_snapshot_id"]},
                                     sort=[("created_at", -1), ("_id", -1)])


def get(db: Database, project_id: ObjectId, score_id: str) -> dict[str, Any] | None:
    if not ObjectId.is_valid(score_id):
        return None
    return db[TRUST_SCORES].find_one({"_id": ObjectId(score_id), "project_id": project_id})


def series(db: Database, project_id: ObjectId, limit: int) -> list[dict[str, Any]]:
    """Scores newest first, without the per-component detail."""
    return list(db[TRUST_SCORES].find({"project_id": project_id}, SERIES_FIELDS).sort([("created_at", -1), ("_id", -1)]).limit(limit))


def prune(db: Database, project_id: ObjectId, keep: int) -> None:
    old = [doc["_id"] for doc in db[TRUST_SCORES].find({"project_id": project_id}, {"_id": 1}).sort([("created_at", -1), ("_id", -1)]).skip(keep)]
    if old:
        db[TRUST_SCORES].delete_many({"_id": {"$in": old}})


def compare(base: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    """What changed between two stored scores, component by component. A delta is given only where both values are known."""
    def delta(name: str) -> float | None:
        before, after = base.get(name), target.get(name)
        return round(after - before, 1) if isinstance(before, (int, float)) and isinstance(after, (int, float)) else None

    before = {component["name"]: component for component in base.get("components") or []}
    after = {component["name"]: component for component in target.get("components") or []}
    components = []
    for name in after or before:
        old, new = before.get(name, {}), after.get(name, {})
        both = isinstance(old.get("risk"), (int, float)) and isinstance(new.get("risk"), (int, float))
        change = "UNCHANGED"
        if old.get("status") != new.get("status"):
            change = "BECAME_KNOWN" if new.get("status") == "KNOWN" else "BECAME_UNKNOWN"
        elif both and abs(new["risk"] - old["risk"]) >= 0.05:
            change = "RISK_UP" if new["risk"] > old["risk"] else "RISK_DOWN"
        components.append({"name": name, "label": new.get("label") or old.get("label"), "weight": new.get("weight") or old.get("weight"),
                           "before": {"status": old.get("status"), "risk": old.get("risk")}, "after": {"status": new.get("status"), "risk": new.get("risk")},
                           "risk_delta": round(new["risk"] - old["risk"], 1) if both else None, "change": change})
    describe = lambda doc: {"id": doc["_id"], "created_at": doc.get("created_at"), "status": doc.get("status"), "trust_score": doc.get("trust_score"),   # noqa: E731
                            "risk_score": doc.get("risk_score"), "confidence": doc.get("confidence"), "coverage": doc.get("coverage"),
                            "snapshot_id": doc.get("snapshot_id"), "commit_sha": doc.get("commit_sha"), "model_version": doc.get("model_version")}
    return {
        "base": describe(base), "target": describe(target),
        "same_snapshot": base.get("snapshot_id") == target.get("snapshot_id"), "same_model": base.get("model_version") == target.get("model_version"),
        "trust_delta": delta("trust_score"), "risk_delta": delta("risk_score"), "confidence_delta": delta("confidence"),
        "coverage_delta": round(target.get("coverage", 0) - base.get("coverage", 0), 2),
        "components": components, "changed": [component["name"] for component in components if component["change"] != "UNCHANGED"],
        "note": None if delta("trust_score") is not None else "At least one of the two has no score (insufficient data), so no score difference is given.",
    }

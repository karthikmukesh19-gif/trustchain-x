"""The trust analysis job and its reads. The calculation itself lives in app.services.trust."""

from __future__ import annotations

from typing import Any

from bson import ObjectId
from pymongo.database import Database

from app.models.collections import PROJECTS, TRUST_SCORES
from app.services import jobs, layers, runs
from app.services.jobs import JobContext, JobError
from app.services.trust import MODEL_VERSION, compute, history
from app.services.trust.explanation import explain


def evidence_of(collected: dict[str, Any]) -> list[dict[str, Any]]:
    """The stored record each layer's contribution was read from."""
    return [{"layer": name, "label": layers.LAYER_LABELS[name], "status": collected[name]["status"], "reference": collected[name]["reference"],
             "as_of": collected[name]["as_of"]} for name in layers.LAYER_NAMES]


def input_digest(collected: dict[str, Any], min_coverage: float) -> str:
    return runs.digest({"model": MODEL_VERSION, "min_coverage": min_coverage,
                        "layers": {name: [collected[name]["status"], collected[name]["reference"], collected[name]["as_of"]]
                                   for name in layers.LAYER_NAMES},
                        # Values the references alone do not pin down.
                        "sbom_verified": collected["sbom"].get("verified"), "dataset_quality": collected["dataset"].get("quality_score"),
                        "commits": collected["commits"].get("analysed_total")})


def _run(context: JobContext, job: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    db, settings = context.db, context.settings
    project = db[PROJECTS].find_one({"_id": job["project_id"]})
    if project is None:
        raise JobError("PROJECT_NOT_FOUND", "The project was deleted before the job started.")
    jobs.progress(db, job, "COMPONENTS", "Reading the stored result of every layer")
    collected = layers.collect(db, project)
    if collected["snapshot"] is None:
        raise JobError("NOT_ANALYSED", "Run a dependency analysis first: there is no snapshot to assess.")
    digest = input_digest(collected, settings.trust_min_coverage)
    previous = history.latest(db, project)
    if previous is not None and previous.get("input_digest") == digest:
        return ("Nothing has changed since the previous trust analysis; it was kept",
                {"summary": _summary(previous, reused=True), "snapshot_id": previous["snapshot_id"]})

    jobs.progress(db, job, "SCORING", "Calculating the risk and trust scores")
    result = compute(collected, settings.trust_min_coverage)
    document = history.store(db, {
        "_id": ObjectId(), "project_id": project["_id"], "repository_id": project.get("repository_id"),
        "snapshot_id": collected["snapshot"]["id"], "commit_sha": collected["snapshot"].get("commit_sha"),
        "branch": collected["snapshot"].get("branch"), "job_id": job["_id"], "created_at": runs.now(), "input_digest": digest,
        **result, "evidence": evidence_of(collected), "explanation": explain(result),
    })
    history.prune(db, project["_id"], max(settings.intelligence_history_limit, 10) * 4)
    if result["status"] == "SCORED":
        message = f"Trust score {result['trust_score']} (risk {result['risk_score']}), confidence {result['confidence']}"
    else:
        message = f"Insufficient data: {result['coverage']:.0%} of the model's weight is covered by analysed layers"
    return message, {"summary": _summary(document, reused=False), "snapshot_id": document["snapshot_id"]}


def _summary(document: dict[str, Any], reused: bool) -> dict[str, Any]:
    return {"trust_score_id": document["_id"], "status": document["status"], "trust_score": document["trust_score"],
            "risk_score": document["risk_score"], "confidence": document["confidence"], "coverage": document["coverage"],
            "unknown_components": document["unknown_components"], "reused": reused}


jobs.handler(jobs.TRUST_ANALYSIS)(_run)


def is_current(db: Database, project: dict[str, Any], score: dict[str, Any], min_coverage: float) -> bool:
    """Whether the layers still look as they did when the score was calculated."""
    return score.get("input_digest") == input_digest(layers.collect(db, project), min_coverage)


def delete_project_data(db: Database, project_id: ObjectId) -> None:
    db[TRUST_SCORES].delete_many({"project_id": project_id})

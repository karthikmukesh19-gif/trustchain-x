"""Cross-layer security reasoning for a project: job, storage, audit trail and reads."""

from __future__ import annotations

from typing import Any

from bson import ObjectId
from pymongo.database import Database

from app.ai import MODEL_VERSION, evidence as evidence_rules
from app.ai import context as context_builder
from app.ai import provider as providers
from app.ai.reasoning import reason
from app.models.collections import AI_FINDINGS, PROJECTS
from app.services import audit, jobs, layers, runs
from app.services.jobs import JobContext, JobError

KIND = "ai"
ROW_COLLECTIONS = (AI_FINDINGS,)


def analyse(db: Database, project: dict[str, Any], provider: providers.ReasoningProvider) -> dict[str, Any]:
    """Findings for the project's current state, each validated against the evidence it cites. Reads only."""
    context = context_builder.build(db, project)
    candidates, trace = reason(context)
    accepted, rejected, explanations = [], [], []
    for finding in candidates:
        evidence = context.store.resolve(finding["evidence_refs"])
        text, record = providers.explain(provider, finding, evidence)
        finding["explanation"] = text
        finding["provider"] = record["provider"]
        problems = evidence_rules.validate(finding, context.store)
        if problems:
            # A finding that is not fully grounded is never stored. It is kept in the audit trail only.
            rejected.append({"finding_id": finding["finding_id"], "rule_id": finding["rule_id"], "problems": problems})
            continue
        finding["evidence"] = evidence
        accepted.append(finding)
        if not record["accepted"]:
            explanations.append({"finding_id": finding["finding_id"], **record})
    return {"context": context, "findings": accepted, "rejected": rejected, "trace": trace, "provider_rejections": explanations,
            "grounding": evidence_rules.grounding(accepted, context.store, len(rejected))}


def _run(context: JobContext, job: dict[str, Any], provider: providers.ReasoningProvider | None = None) -> tuple[str, dict[str, Any]]:
    db, settings = context.db, context.settings
    project = db[PROJECTS].find_one({"_id": job["project_id"]})
    if project is None:
        raise JobError("PROJECT_NOT_FOUND", "The project was deleted before the job started.")
    provider = provider or providers.get_provider(settings.ai_provider)

    jobs.progress(db, job, "CONTEXT", "Reading the stored results of every analysis layer")
    result = analyse(db, project, provider)
    reasoning_context = result["context"]
    if not reasoning_context.layer_evidence:
        raise JobError("NOT_ANALYSED", "No analysis layer has results yet. Run the dependency analysis first.")
    context.check_deadline(settings.intelligence_timeout_seconds)
    snapshot = None if reasoning_context.snapshot is None else {"_id": reasoning_context.snapshot["id"],
                                                                "commit_sha": reasoning_context.snapshot.get("commit_sha"),
                                                                "branch": reasoning_context.snapshot.get("branch")}
    input_digest = runs.digest({"context": reasoning_context.digest(), "model": MODEL_VERSION, "provider": provider.name,
                                "provider_version": provider.model_version, "evidence": len(reasoning_context.store),
                                "findings": [finding["finding_id"] for finding in result["findings"]]})
    existing = runs.reusable(db, project["_id"], KIND, input_digest)
    if existing is not None:
        return ("Nothing has changed since the previous analysis; it was kept",
                {"summary": {**(existing.get("summary") or {}), "analysis_id": existing["_id"], "reused": True}, "analysis_id": existing["_id"]})

    jobs.progress(db, job, "REASONING", f"{len(result['findings'])} finding(s) from {len(reasoning_context.store)} evidence item(s)")
    run = runs.begin(db, project=project, snapshot=snapshot, kind=KIND, job=job, model_version=MODEL_VERSION, input_digest=input_digest,
                     inputs={"provider": provider.name, "provider_version": provider.model_version,
                             "layers": {name: reasoning_context.layers[name]["status"] for name in layers.LAYER_NAMES},
                             "layer_references": {name: reasoning_context.layers[name]["reference"] for name in layers.LAYER_NAMES}})
    scope = {"analysis_id": run["_id"], "project_id": project["_id"], "repository_id": project.get("repository_id"),
             "snapshot_id": snapshot["_id"] if snapshot else None, "created_at": run["created_at"]}
    jobs.progress(db, job, "VALIDATION", "Storing findings whose every statement cites stored evidence")
    try:
        runs.insert_rows(db, AI_FINDINGS, [{**scope, **finding} for finding in result["findings"]])
    except Exception:
        runs.discard(db, run, ROW_COLLECTIONS)
        raise
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for finding in result["findings"]:
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
        by_category[finding["category"]] = by_category.get(finding["category"], 0) + 1
    summary = {
        "findings": len(result["findings"]), "by_severity": by_severity, "by_category": by_category, "grounding": result["grounding"],
        "provider": provider.name, "provider_version": provider.model_version, "deterministic": provider.deterministic,
        "rules": result["trace"], "rejected_findings": result["rejected"][:50], "provider_rejections": result["provider_rejections"][:50],
        "layers_missing": [gap["layer"] for gap in layers.missing(reasoning_context.layers)], "evidence_items": len(reasoning_context.store),
        "top": [{"finding_id": f["finding_id"], "category": f["category"], "severity": f["severity"]} for f in result["findings"][:5]],
        "reused": False,
    }
    runs.complete(db, run, summary)
    runs.prune(db, project["_id"], KIND, settings.intelligence_history_limit, ROW_COLLECTIONS)
    # The audit trail: what reasoned, over which inputs, with what outcome. Kept apart from the findings themselves.
    audit.record(db, "ai.reasoning.complete", actor_id=project.get("owner_id"), resource_type="project", resource_id=project["_id"],
                 details={"analysis_id": str(run["_id"]), "model_version": MODEL_VERSION, "provider": provider.name,
                          "findings": len(result["findings"]), "rejected": len(result["rejected"]),
                          "provider_rejections": len(result["provider_rejections"]), "evidence_items": len(reasoning_context.store),
                          "evidence_grounding": result["grounding"]["evidence_grounding"], "input_digest": input_digest[:16]})
    serious = sum(count for severity, count in by_severity.items() if severity in ("HIGH", "CRITICAL"))
    return (f"{len(result['findings'])} finding(s), {serious} of high or critical severity; every statement cites stored evidence",
            {"summary": {**summary, "analysis_id": run["_id"]}, "analysis_id": run["_id"]})


jobs.handler(jobs.AI_SECURITY_ANALYSIS)(_run)


def latest(db: Database, project: dict[str, Any]) -> dict[str, Any] | None:
    return runs.latest(db, project, KIND, snapshot_bound=project.get("latest_snapshot_id") is not None)


def delete_project_data(db: Database, project_id: ObjectId) -> None:
    for collection in ROW_COLLECTIONS:
        db[collection].delete_many({"project_id": project_id})

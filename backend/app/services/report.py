"""The project report: seventeen sections built from stored results, every statement carrying its evidence.

A statement is {basis, text, evidence}: `basis` says how it is known
(OBSERVED, DERIVED, PREDICTED, RECOMMENDED, or METHOD for a statement about
how the platform works) and `evidence` lists references into the report's
evidence index. `unsupported` returns the statements that carry none; the
report is only served when that list is empty.
"""

from __future__ import annotations

from typing import Any

from pymongo.database import Database

from app.ai import MODEL_VERSION as REASONING_MODEL
from app.analyzers.attack_paths import MODEL_VERSION as ATTACK_PATH_MODEL
from app.analyzers.behavior import MODEL_VERSION as COMMIT_MODEL
from app.analyzers.dataset import MODEL_VERSION as DATASET_MODEL
from app.analyzers.dataset.validation import LIMITATION as DATASET_LIMITATION
from app.analyzers.maintainers import MODEL_VERSION as MAINTAINER_MODEL
from app.models.collections import (
    AI_FINDINGS, ATTACK_PATHS, CODE_REACHABILITY, DATASET_QUALITY, DEPENDENCY_FRAGILITY, PREDICTIONS, PREDICTIVE_INDICATORS, SECURITY_EVENTS,
    VULNERABILITY_MATCHES,
)
from app.services import layers, runs
from app.services.trust import MODEL_VERSION as TRUST_MODEL
from app.services.trust import WEIGHTS, WEIGHTS_STATEMENT
from app.services.trust import history as trust_history

OBSERVED, DERIVED, PREDICTED, RECOMMENDED, METHOD = "OBSERVED", "DERIVED", "PREDICTED", "RECOMMENDED", "METHOD"
SECTIONS = (
    ("executive_summary", "Executive Summary"), ("trust_score", "Trust Score"), ("risk_score", "Risk Score"),
    ("vulnerability_findings", "Vulnerability Findings"), ("sbom_integrity", "SBOM Integrity"), ("dependency_fragility", "Dependency Fragility"),
    ("code_reachability", "Code Reachability"), ("attack_paths", "Attack Paths"), ("maintainer_behaviour", "Maintainer Behaviour"),
    ("commit_behaviour", "Commit Behaviour"), ("ai_findings", "AI Cross-Layer Findings"), ("dataset_quality", "Dataset Quality"),
    ("predictive_indicators", "Predictive Indicators"), ("recommendations", "Recommendations"), ("evidence", "Evidence"),
    ("methodology", "Methodology"), ("limitations", "Limitations"),
)
ROWS = 15
LIMITATIONS = (
    "The analysis is static. No repository code was executed, no exploit was attempted, and nothing here shows that an attack would succeed.",
    "Vulnerability findings cover advisories published by the configured source for package versions that could be resolved. An absent finding "
    "is not evidence of absence: unpublished weaknesses are not detected.",
    "Code reachability is implemented for Python source. For other languages reachability is reported as unsupported and counted as undecided.",
    "Maintainer and commit indicators describe patterns in public metadata and diffs. They are not judgements about people, and no indicator "
    "identifies intent.",
    "Predictive and fragility scores are model outputs for prioritising attention. They are not probabilities and forecast no specific event.",
    DATASET_LIMITATION,
    WEIGHTS_STATEMENT + " A different weighting would give a different score from the same evidence.",
    "Accuracy measures (precision, recall, calibration) have not been evaluated against labelled benchmark data and are not claimed.",
)


class Builder:
    """Collects sections and the evidence index while the report is assembled."""

    def __init__(self) -> None:
        self.sections: list[dict[str, Any]] = []
        self.index: dict[tuple[str, str], dict[str, Any]] = {}

    def cite(self, layer: str, collection: str, record_id: Any, as_of: Any = None, note: str | None = None) -> str:
        key = (collection, str(record_id))
        if key not in self.index:
            self.index[key] = {"ref": f"R{len(self.index) + 1}", "kind": "record", "layer": layer, "collection": collection,
                               "record_id": record_id, "as_of": as_of, "note": note}
        return self.index[key]["ref"]

    def method(self, document: str, model_version: str | None = None) -> str:
        key = ("method", f"{document}|{model_version}")
        if key not in self.index:
            self.index[key] = {"ref": f"R{len(self.index) + 1}", "kind": "method", "layer": "method", "collection": None, "record_id": None,
                               "document": document, "model_version": model_version, "as_of": None, "note": None}
        return self.index[key]["ref"]

    def layer(self, name: str, layer: dict[str, Any]) -> str | None:
        reference = layer.get("reference")
        return self.cite(name, reference["collection"], reference["id"], layer.get("as_of")) if reference else None

    def section(self, identifier: str) -> "Section":
        title = dict(SECTIONS)[identifier]
        section = Section(self, {"number": len(self.sections) + 1, "id": identifier, "title": title, "available": True, "statements": [],
                                 "tables": []})
        self.sections.append(section.data)
        return section


class Section:
    def __init__(self, builder: Builder, data: dict[str, Any]) -> None:
        self.builder, self.data = builder, data

    def say(self, basis: str, text: str, *refs: str | None) -> "Section":
        self.data["statements"].append({"basis": basis, "text": text, "evidence": [ref for ref in refs if ref]})
        return self

    def table(self, title: str, columns: list[str], rows: list[dict[str, Any]]) -> "Section":
        """Rows are {"cells": [...], "evidence": [refs]}: every row points at the record it was read from."""
        if rows:
            self.data["tables"].append({"title": title, "columns": columns, "rows": rows})
        return self

    def unavailable(self, name: str, layer: dict[str, Any], anchor: str | None) -> "Section":
        self.data["available"] = False
        reason = {"NOT_ANALYSED": "has not been analysed", "STALE": "has results only for an earlier snapshot",
                  "UNAVAILABLE": "could not collect its data"}.get(layer["status"], "has no usable result")
        return self.say(DERIVED, f"{layers.LAYER_LABELS[name]} {reason} for this snapshot. This section therefore reports nothing; the absence "
                                 f"of findings here is not a clean result. {layers.HOW_TO_RUN[name]}", anchor)


def unsupported(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Statements and table rows that cite no evidence, or cite a reference that is not in the evidence index."""
    known = {item["ref"] for item in report["evidence"]}
    problems = []
    for section in report["sections"]:
        for statement in section["statements"]:
            if not statement["evidence"] or any(ref not in known for ref in statement["evidence"]):
                problems.append({"section": section["id"], "text": statement["text"]})
        for table in section["tables"]:
            for row in table["rows"]:
                if not row["evidence"] or any(ref not in known for ref in row["evidence"]):
                    problems.append({"section": section["id"], "text": f"row of '{table['title']}'"})
    return problems


def build(db: Database, project: dict[str, Any]) -> dict[str, Any]:
    collected = layers.collect(db, project)
    b = Builder()
    snapshot = collected["snapshot"]
    project_ref = b.cite("project", "projects", project["_id"], project.get("created_at"))
    anchor = b.cite("inventory", "repository_snapshots", snapshot["id"], snapshot.get("collected_at")) if snapshot else project_ref
    trust = trust_history.latest(db, project)
    trust_ref = b.cite("trust", "trust_scores", trust["_id"], trust["created_at"]) if trust else None
    ref = {name: b.layer(name, collected[name]) for name in (*layers.LAYER_NAMES, "ai")}

    def ok(name: str) -> bool:
        return bool(collected[name]["available"])

    # 1 ----------------------------------------------------------------------------------
    s = b.section("executive_summary")
    if snapshot:
        s.say(OBSERVED, f"This report describes project '{project.get('name')}' ({project.get('repository_url')}) at commit "
                        f"{snapshot.get('commit_sha')} on branch {snapshot.get('branch')}.", anchor)
    else:
        s.say(OBSERVED, f"Project '{project.get('name')}' ({project.get('repository_url')}) has not been analysed: no snapshot exists.", project_ref)
    if trust and trust["status"] == "SCORED":
        s.say(DERIVED, f"The trust score is {trust['trust_score']} of 100 (risk {trust['risk_score']}) with confidence {trust['confidence']}; "
                       f"{trust['coverage']:.0%} of the model's weight rests on analysed layers.", trust_ref)
    elif trust:
        s.say(DERIVED, f"INSUFFICIENT DATA: no trust score is given. {trust.get('insufficient_reason', '')}", trust_ref)
    else:
        s.say(DERIVED, "No trust analysis has been run for this snapshot, so no trust score is given.", anchor)
    if ok("vulnerabilities"):
        v = collected["vulnerabilities"]
        s.say(OBSERVED, f"{v['distinct_vulnerabilities']} distinct known vulnerabilit(ies) affect {v['affected_dependencies']} of "
                        f"{v['dependencies_total']} packages.", ref["vulnerabilities"])
    if ok("reachability") and collected["reachability"].get("findings"):
        by_status = collected["reachability"]["by_status"]
        s.say(DERIVED, f"Static analysis finds {by_status.get('REACHABLE', 0)} of them reached by application code; "
                       f"{by_status.get('UNKNOWN', 0) + by_status.get('UNSUPPORTED', 0)} are undecided.", ref["reachability"])
    if ok("ai"):
        by_severity = collected["ai"]["summary"].get("by_severity") or {}
        serious = by_severity.get("CRITICAL", 0) + by_severity.get("HIGH", 0)
        s.say(DERIVED, f"Cross-layer reasoning produced {collected['ai']['summary'].get('findings', 0)} finding(s), {serious} of high or critical "
                       "severity.", ref["ai"])
    gaps = layers.missing(collected)
    if gaps:
        s.say(DERIVED, f"{len(gaps)} of {len(layers.LAYER_NAMES)} analysis layers have no usable result: {', '.join(gap['label'] for gap in gaps)}. "
                       "Their sections below say so; nothing is assumed for them.", anchor)

    # 2, 3 -------------------------------------------------------------------------------
    s = b.section("trust_score")
    risk = b.section("risk_score")
    if trust is None:
        for section in (s, risk):
            section.data["available"] = False
            section.say(DERIVED, "No trust analysis has been run for this snapshot. Run the trust analysis after the other layers.", anchor)
    else:
        model = b.method("docs/phase11.md", trust["model_version"])
        if trust["status"] == "SCORED":
            s.say(DERIVED, f"Trust score: {trust['trust_score']} of 100 ({str(trust['band']).replace('_', ' ').lower()}). Confidence: {trust['confidence']}.", trust_ref)
            risk.say(DERIVED, f"Risk score: {trust['risk_score']} of 100. {trust['explanation']['calculation']['worked']}.", trust_ref)
        else:
            s.say(DERIVED, f"INSUFFICIENT DATA. {trust.get('insufficient_reason', '')}", trust_ref)
            risk.say(DERIVED, "No risk score is given, for the same reason that no trust score is given.", trust_ref)
        s.say(DERIVED, f"Depending on the components that are unknown, the trust score lies between {trust['trust_low']} and {trust['trust_high']}.", trust_ref)
        s.say(METHOD, "Trust is 100 minus risk. Risk is the weighted mean of the component risks that are known. " + WEIGHTS_STATEMENT, model)
        risk.say(DERIVED, trust["explanation"]["calculation"]["bounds"], trust_ref)
        rows = [{"cells": [c["label"], c["weight"], c["status"], "—" if c["risk"] is None else c["risk"],
                           "—" if c["contribution"] is None else c["contribution"], c["confidence"], c["detail"]],
                 "evidence": [trust_ref, b.cite(c["layer"], c["reference"]["collection"], c["reference"]["id"], c.get("as_of")) if c.get("reference") else None]}
                for c in trust["components"]]
        for row in rows:
            row["evidence"] = [item for item in row["evidence"] if item]
        risk.table("Component risks", ["Component", "Weight", "Status", "Risk", "Contribution", "Confidence", "Basis of the value"], rows)
        for item in trust["explanation"]["top_risks"]:
            risk.say(DERIVED, f"{item['label']} accounts for {item['contribution']} points of the risk score: {item['detail']}", trust_ref)

    # 4 ----------------------------------------------------------------------------------
    s = b.section("vulnerability_findings")
    if not ok("vulnerabilities"):
        s.unavailable("vulnerabilities", collected["vulnerabilities"], anchor)
    else:
        v = collected["vulnerabilities"]
        severities = ", ".join(f"{count} {name.lower()}" for name, count in (v.get("by_severity") or {}).items() if count) or "none"
        s.say(OBSERVED, f"{v['affected_matches']} advisory match(es) were found for {v['dependencies_checked']} checked package version(s); "
                        f"by severity: {severities}.", ref["vulnerabilities"])
        unchecked = (v.get("dependencies_total") or 0) - (v.get("dependencies_checked") or 0)
        if unchecked > 0:
            s.say(OBSERVED, f"{unchecked} package(s) could not be checked (no resolved version, or an ecosystem the source does not cover).",
                  ref["vulnerabilities"])
        rows = [{"cells": [m.get("package_name"), m.get("matched_version"), m.get("source_id"), m.get("severity"),
                           ", ".join((m.get("fixed_versions") or [])[:3]) or "—", m.get("relationship")],
                 "evidence": [b.cite("vulnerabilities", VULNERABILITY_MATCHES, m["_id"], m.get("matched_at"))]}
                for m in db[VULNERABILITY_MATCHES].find({"project_id": project["_id"], "snapshot_id": snapshot["id"], "match_status": "AFFECTED"})
                .sort([("severity_rank", -1), ("source_id", 1)]).limit(ROWS)]
        s.table("Advisory matches (highest severity first)", ["Package", "Version", "Advisory", "Severity", "Fixed in", "Relationship"], rows)

    # 5 ----------------------------------------------------------------------------------
    s = b.section("sbom_integrity")
    if not ok("sbom"):
        s.unavailable("sbom", collected["sbom"], anchor)
    else:
        sbom = collected["sbom"]
        s.say(OBSERVED, f"SBOM version {sbom['version']} lists {sbom['component_count']} component(s); its content digest (SHA-256) is "
                        f"{sbom['content_digest']}.", ref["sbom"])
        if sbom["verified"] is True:
            s.say(OBSERVED, "Integrity verification passed: the stored document matches its recorded digests and a fresh generation from the snapshot.",
                  ref["sbom"])
        elif sbom["verified"] is False:
            failed = ", ".join((sbom.get("verification") or {}).get("failed_checks") or [])
            s.say(OBSERVED, f"Integrity verification FAILED ({failed}). The SBOM should not be relied on.", ref["sbom"])
        else:
            s.say(OBSERVED, "The SBOM has not been verified. Its integrity is unknown.", ref["sbom"])

    # 6 ----------------------------------------------------------------------------------
    s = b.section("dependency_fragility")
    if not ok("fragility"):
        s.unavailable("fragility", collected["fragility"], anchor)
    else:
        summary = collected["fragility"]["summary"]
        s.say(DERIVED, f"{summary.get('dependencies')} dependencies were scored: mean fragility {summary.get('mean')}, highest {summary.get('highest')} "
                       f"(of 100); by level {summary.get('by_level')}.", ref["fragility"])
        rows = [{"cells": [r.get("package_name"), r.get("version") or "unresolved", r.get("fragility_score"), r.get("fragility_level"), r.get("confidence")],
                 "evidence": [b.cite("fragility", DEPENDENCY_FRAGILITY, r["_id"], r.get("created_at"))]}
                for r in db[DEPENDENCY_FRAGILITY].find({"analysis_id": collected["fragility"]["reference"]["id"]})
                .sort([("fragility_score", -1), ("node_id", 1)]).limit(10)]
        s.table("Most fragile dependencies", ["Package", "Version", "Fragility", "Level", "Confidence"], rows)

    # 7 ----------------------------------------------------------------------------------
    s = b.section("code_reachability")
    if not ok("reachability"):
        s.unavailable("reachability", collected["reachability"], anchor)
    else:
        reach = collected["reachability"]
        s.say(DERIVED, f"{reach['findings']} vulnerability finding(s) were evaluated; by status {reach['by_status']}. "
                       f"Languages analysed: {', '.join(reach['languages']) or 'none'}.", ref["reachability"])
        s.say(METHOD, "REACHABLE means source code statically refers to the affected functionality. It is not a statement about exploitability; "
                      "NOT_CONFIRMED_REACHABLE does not clear the code: it means no path was established.", b.method("docs/phase4.md", reach.get("analyzer_version")))
        rows = [{"cells": [f.get("dependency"), f.get("advisory_id"), f.get("status"), f.get("confidence") or "—",
                           f"{(f.get('evidence') or {}).get('source_file')}:{(f.get('evidence') or {}).get('line')}" if (f.get("evidence") or {}).get("source_file") else "—"],
                 "evidence": [b.cite("reachability", CODE_REACHABILITY, f["_id"], f.get("analyzed_at"))]}
                for f in db[CODE_REACHABILITY].find({"analysis_id": reach["reference"]["id"]}).sort([("status_rank", -1), ("severity_rank", -1), ("advisory_id", 1)]).limit(ROWS)]
        s.table("Reachability findings (reachable first)", ["Package", "Advisory", "Status", "Confidence", "Source location"], rows)

    # 8 ----------------------------------------------------------------------------------
    s = b.section("attack_paths")
    if not ok("attack_paths"):
        s.unavailable("attack_paths", collected["attack_paths"], anchor)
    else:
        summary = collected["attack_paths"]["summary"]
        s.say(DERIVED, f"The simulation built {summary.get('paths', 0)} path(s) from stored evidence; by status {summary.get('by_status')}. "
                       f"Highest score: {summary.get('highest_score')}.", ref["attack_paths"])
        s.say(METHOD, "A path is a static reading of the dependency graph, advisory matches and reachability findings. No path was exercised, and "
                      "no path shows that an attack would succeed.", b.method("docs/phase6.md", ATTACK_PATH_MODEL))
        rows = [{"cells": [p["target"].get("package_name"), p["advisory"].get("source_id"), p["status"], p["score"], p["confidence"],
                           " → ".join(p.get("route") or []) or "no recorded chain"],
                 "evidence": [b.cite("attack_paths", ATTACK_PATHS, p["attack_path_id"], p.get("created_at"))]}
                for p in db[ATTACK_PATHS].find({"analysis_id": collected["attack_paths"]["reference"]["id"]})
                .sort([("score", -1), ("attack_path_id", 1)]).limit(10)]
        s.table("Highest-scoring attack paths", ["Package", "Advisory", "Status", "Score", "Confidence", "Dependency chain"], rows)

    # 9 ----------------------------------------------------------------------------------
    s = b.section("maintainer_behaviour")
    if not ok("maintainers"):
        s.unavailable("maintainers", collected["maintainers"], anchor)
    else:
        m = collected["maintainers"]
        s.say(DERIVED, f"{m['contributor_count']} contributor(s) were observed in {m['commits_observed']} commit(s). Attention score "
                       f"{m['attention_score']} of 100 with confidence {m['confidence']}.", ref["maintainers"])
        s.say(METHOD, "Indicators describe patterns in public repository metadata. They are not judgements about people and no indicator "
                      "identifies intent.", b.method("docs/phase7.md", MAINTAINER_MODEL))
        s.table("Behavioural indicators", ["Indicator", "Status", "Detail"],
                [{"cells": [item["type"], item["status"], item.get("detail")], "evidence": [ref["maintainers"]]} for item in m["indicators"]])

    # 10 ---------------------------------------------------------------------------------
    s = b.section("commit_behaviour")
    if not ok("commits"):
        s.unavailable("commits", collected["commits"], anchor)
    elif not collected["commits"]["analysed_total"]:
        s.say(DERIVED, "The repository has no commits that could be analysed.", ref["commits"])
    else:
        c = collected["commits"]
        s.say(DERIVED, f"{c['analysed_total']} commit(s) have been analysed. Over the latest {c['window']}, the highest anomaly score is "
                       f"{c['highest_anomaly']} and the mean {c['mean_anomaly']}; {c['security_events']} event(s) are listed for review.", ref["commits"])
        s.say(METHOD, "An anomaly is a departure from this repository's own earlier commits. Events are reasons to review a change, not "
                      "confirmed incidents. Secret-like values are never stored.", b.method("docs/phase8.md", COMMIT_MODEL))
        rows = [{"cells": [e["commit_sha"][:10], e["event_type"], e["severity"], e["observed_or_inferred"], e.get("summary")],
                 "evidence": [b.cite("commits", SECURITY_EVENTS, e["_id"], e.get("occurred_at"))]}
                for e in db[SECURITY_EVENTS].find({"project_id": project["_id"]}).sort([("occurred_at", -1), ("severity_rank", -1), ("event_type", 1)]).limit(ROWS)]
        s.table("Events listed for security review (newest first)", ["Commit", "Event", "Severity", "Observed or inferred", "Summary"], rows)

    # 11 ---------------------------------------------------------------------------------
    s = b.section("ai_findings")
    findings: list[dict[str, Any]] = []
    if not ok("ai"):
        s.data["available"] = False
        s.say(DERIVED, "Cross-layer reasoning has not been run for this snapshot. Run the AI security analysis.", anchor)
    else:
        summary = collected["ai"]["summary"]
        grounding = summary.get("grounding") or {}
        s.say(DERIVED, f"{summary.get('findings', 0)} finding(s) were produced by the {summary.get('provider')} provider from "
                       f"{summary.get('evidence_items')} evidence item(s). Measured evidence grounding: {grounding.get('evidence_grounding')}; "
                       f"unsupported-claim rate: {grounding.get('unsupported_claim_rate')}.", ref["ai"])
        s.say(METHOD, "Findings come from fixed rules over stored results. A finding whose statements do not all cite existing evidence is "
                      "rejected before it is stored.", b.method("docs/phase9.md", REASONING_MODEL))
        findings = list(db[AI_FINDINGS].find({"analysis_id": collected["ai"]["reference"]["id"]})
                        .sort([("severity_rank", -1), ("confidence", -1), ("finding_id", 1)]).limit(ROWS))
        s.table("Findings (most severe first)", ["Category", "Severity", "Confidence", "Layers", "Finding"],
                [{"cells": [f["category"], f["severity"], f["confidence"], ", ".join(f["contributing_layers"]),
                            " ".join(item["text"] for item in f["statements"])],
                  "evidence": [b.cite("ai", AI_FINDINGS, f["finding_id"], f.get("created_at"))]} for f in findings])

    # 12 ---------------------------------------------------------------------------------
    s = b.section("dataset_quality")
    if not ok("dataset"):
        s.unavailable("dataset", collected["dataset"], anchor)
    else:
        d = collected["dataset"]
        s.say(DERIVED, f"Dataset version {d['version']} holds {d['record_count']} record(s); dataset hash (SHA-256) {d['dataset_hash']}. "
                       f"Validation status: {d['quality_status']}; quality score {d['quality_score']}; confidence {d['quality_confidence']}.", ref["dataset"])
        quality = db[DATASET_QUALITY].find_one({"dataset_id": d["dataset_id"]}, sort=[("created_at", -1), ("_id", -1)])
        if quality:
            quality_ref = b.cite("dataset", DATASET_QUALITY, quality["_id"], quality.get("created_at"))
            s.table("Quality factors", ["Factor", "Weight", "Value", "Detail"],
                    [{"cells": [f["name"], f["weight"], "unknown" if f["value"] is None else f["value"], f["detail"]], "evidence": [quality_ref]}
                     for f in quality.get("factors") or []])
            for warning in (quality.get("warnings") or [])[:8]:
                s.say(DERIVED, warning, quality_ref)
        s.say(METHOD, DATASET_LIMITATION, b.method("docs/phase10.md", DATASET_MODEL))

    # 13 ---------------------------------------------------------------------------------
    s = b.section("predictive_indicators")
    if not ok("predictive"):
        s.unavailable("predictive", collected["predictive"], anchor)
    else:
        summary = collected["predictive"]["summary"]
        s.say(PREDICTED, f"{summary.get('dependencies')} dependencies were assessed; by level {summary.get('by_level')}. "
                         f"{summary.get('indicator_total', 0)} predictive indicator(s) were raised: {summary.get('indicators') or {}}.", ref["predictive"])
        s.say(METHOD, "Predictive dependency risk is a relative priority for monitoring. It is not a probability and predicts no specific event.",
              b.method("docs/phase5.md", collected["predictive"].get("model_version")))
        reference = collected["predictive"]["reference"]["id"]
        s.table("Dependencies ranked highest", ["Package", "Version", "Predictive risk", "Level", "Indicators"],
                [{"cells": [r.get("package_name"), r.get("version") or "unresolved", r.get("score"), r.get("level"),
                            ", ".join(r.get("indicator_types") or []) or "—"],
                  "evidence": [b.cite("predictive", PREDICTIONS, r["_id"], r.get("created_at"))]}
                 for r in db[PREDICTIONS].find({"analysis_id": reference}).sort([("score", -1), ("node_id", 1)]).limit(10)])
        s.table("Indicators raised", ["Indicator", "Package", "Detail"],
                [{"cells": [r.get("type"), r.get("package_name"), r.get("detail") or r.get("explanation") or "—"],
                  "evidence": [b.cite("predictive", PREDICTIVE_INDICATORS, r["_id"], r.get("created_at"))]}
                 for r in db[PREDICTIVE_INDICATORS].find({"analysis_id": reference}).sort([("type", 1), ("node_id", 1)]).limit(ROWS)])

    # 14 ---------------------------------------------------------------------------------
    s = b.section("recommendations")
    count = 0
    if trust:
        for item in trust["explanation"]["recommendations"][:8]:
            count += 1
            s.say(RECOMMENDED, f"{item['text']} (Because: {item['because']})", trust_ref)
    for finding in findings[:8]:
        if finding["severity"] in ("CRITICAL", "HIGH", "MEDIUM"):
            count += 1
            s.say(RECOMMENDED, finding["recommendation"]["text"], b.cite("ai", AI_FINDINGS, finding["finding_id"], finding.get("created_at")))
    if not count:
        for gap in gaps[:8]:
            s.say(RECOMMENDED, f"{gap['action']} {gap['label']} is {gap['status'].replace('_', ' ').lower()}.", anchor)
    if not s.data["statements"]:
        s.say(RECOMMENDED, "No recommendation follows from the stored results. Keep the analyses current as the repository changes.", anchor)

    # 16, 17 are built before 15 so that the evidence index is complete when it is written ---
    methodology = {"number": 16, "id": "methodology", "title": dict(SECTIONS)["methodology"], "available": True, "statements": [], "tables": []}
    m = Section(b, methodology)
    m.say(METHOD, "Every result is labelled by how it is known: OBSERVED (read from the repository or an advisory source), DERIVED (computed "
                  "from observed data by a documented analysis), PREDICTED (a model's estimate) or RECOMMENDED (a suggested action).",
          b.method("docs/architecture.md"))
    m.say(METHOD, "Repository content is read through the GitHub API and parsed as data. No repository code is executed at any stage.",
          b.method("docs/security.md"))
    m.say(METHOD, "A layer that has not been analysed is reported as such. Unknown values are never shown as zero and never counted as favourable.",
          b.method("docs/architecture.md"))
    m.table("Model versions used", ["Layer", "Model", "Documentation"], [
        {"cells": [label, version, document], "evidence": [b.method(document, version)]} for label, version, document in (
            ("Attack-path simulation", ATTACK_PATH_MODEL, "docs/phase6.md"), ("Maintainer behaviour", MAINTAINER_MODEL, "docs/phase7.md"),
            ("Commit behaviour", COMMIT_MODEL, "docs/phase8.md"), ("Cross-layer reasoning", REASONING_MODEL, "docs/phase9.md"),
            ("Dataset quality", DATASET_MODEL, "docs/phase10.md"), ("Trust engine", TRUST_MODEL, "docs/phase11.md"))])
    m.table("Trust model weights", ["Component", "Weight"],
            [{"cells": [name.replace("_", " "), weight], "evidence": [b.method("docs/phase11.md", TRUST_MODEL)]} for name, weight in WEIGHTS.items()])
    limitations = {"number": 17, "id": "limitations", "title": dict(SECTIONS)["limitations"], "available": True, "statements": [], "tables": []}
    limits = Section(b, limitations)
    for text in LIMITATIONS:
        limits.say(METHOD, text, b.method("docs/research-validation.md"))

    # 15 ---------------------------------------------------------------------------------
    s = b.section("evidence")
    records = [item for item in b.index.values() if item["kind"] == "record"]
    s.say(DERIVED, f"This report cites {len(records)} stored record(s) and {len(b.index) - len(records)} method reference(s). Each reference "
                   "below names the collection and identifier of the record a statement was read from.", anchor)
    s.table("Layer status", ["Layer", "Status", "As of"],
            [{"cells": [layers.LAYER_LABELS[name], collected[name]["status"], collected[name]["as_of"]], "evidence": [ref[name] or anchor]}
             for name in layers.LAYER_NAMES])
    b.sections += [methodology, limitations]

    report = {
        "title": f"TrustChain-X report: {project.get('name')}", "generated_at": runs.now(),
        "project": {"id": project["_id"], "name": project.get("name"), "repository_url": project.get("repository_url")},
        "snapshot": snapshot, "sections": b.sections, "evidence": list(b.index.values()),
        "statement_count": sum(len(section["statements"]) for section in b.sections),
        "bases": [OBSERVED, DERIVED, PREDICTED, RECOMMENDED, METHOD],
    }
    report["unsupported_statements"] = unsupported(report)
    return report


def to_markdown(report: dict[str, Any]) -> str:
    """The report as Markdown. Statements keep their basis label and evidence references."""
    def cell(value: Any) -> str:
        text = "—" if value is None else str(value)
        return text.replace("|", "\\|").replace("\n", " ")

    snapshot = report.get("snapshot") or {}
    lines = [f"# {report['title']}", "", f"Generated: {report['generated_at']:%Y-%m-%d %H:%M} UTC  ",
             f"Repository: {report['project']['repository_url']}  ", f"Commit: {snapshot.get('commit_sha') or 'not analysed'}", "",
             "Each statement is labelled by how it is known and followed by the evidence references it rests on (see section 15).", ""]
    for section in report["sections"]:
        lines += [f"## {section['number']}. {section['title']}", ""]
        for statement in section["statements"]:
            lines.append(f"- **{statement['basis']}** {statement['text']} ({', '.join(statement['evidence'])})")
        for table in section["tables"]:
            lines += ["", f"**{table['title']}**", "", "| " + " | ".join(table["columns"]) + " | Evidence |",
                      "|" + " --- |" * (len(table["columns"]) + 1)]
            for row in table["rows"]:
                lines.append("| " + " | ".join(cell(value) for value in row["cells"]) + f" | {', '.join(row['evidence'])} |")
        if section["id"] == "evidence":
            lines += ["", "**Evidence index**", "", "| Ref | Kind | Layer | Source | Identifier | As of |", "| --- | --- | --- | --- | --- | --- |"]
            for item in report["evidence"]:
                source = item["collection"] if item["kind"] == "record" else item.get("document")
                identifier = item["record_id"] if item["kind"] == "record" else item.get("model_version")
                lines.append(f"| {item['ref']} | {item['kind']} | {item['layer']} | {cell(source)} | {cell(identifier)} | {cell(item.get('as_of'))} |")
        lines.append("")
    return "\n".join(lines)

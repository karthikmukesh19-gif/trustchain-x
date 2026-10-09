"""Node types of an attack path, one per stage, each carrying the evidence it rests on."""

from __future__ import annotations

from typing import Any

ENTRY, DEPENDENCY, VULNERABILITY = "ENTRY", "DEPENDENCY", "VULNERABILITY"
REACHABILITY, APPLICATION, DOWNSTREAM_COMPONENT, IMPACT = "REACHABILITY", "APPLICATION", "DOWNSTREAM_COMPONENT", "IMPACT"
STAGES = (ENTRY, DEPENDENCY, VULNERABILITY, REACHABILITY, APPLICATION, DOWNSTREAM_COMPONENT, IMPACT)

# How a node is known. OBSERVED: read from the repository or an advisory source. DERIVED: computed from observed
# data by a stated rule. INFERRED: a reasoned step that the evidence makes possible but does not establish.
OBSERVED, DERIVED, INFERRED = "OBSERVED", "DERIVED", "INFERRED"


def node(identifier: str, stage: str, label: str, basis: str, detail: str, evidence: list[dict[str, Any]] | None = None,
         **attributes: Any) -> dict[str, Any]:
    return {"id": identifier, "stage": stage, "label": label, "basis": basis, "detail": detail, "evidence": evidence or [], **attributes}


def entry(project_name: str, declared_in: list[dict[str, Any]]) -> dict[str, Any]:
    files = sorted({item.get("source_file") for item in declared_in if item.get("source_file")})
    where = f"declared in {', '.join(files[:3])}" if files else "no declaring file recorded"
    return node("entry:project", ENTRY, project_name or "Project", OBSERVED,
                f"The project takes in third-party code through its dependency declarations ({where}).",
                [{"type": "dependency_declaration", "basis": OBSERVED, **{k: item.get(k) for k in ("source_file", "line", "declaration")}}
                 for item in declared_in[:3]])


def dependency(document: dict[str, Any], vulnerable: bool = False) -> dict[str, Any]:
    version = document.get("version") or "unresolved version"
    return node(f"dep:{document['node_id']}", DEPENDENCY, f"{document.get('name') or document['node_id']} {version}", OBSERVED,
                document.get("relationship_reason") or f"{document.get('relationship', 'UNKNOWN').title()} dependency.",
                [{"type": "dependency", "basis": OBSERVED, "ref": {"collection": "dependencies", "id": document.get("_id")},
                  "node_id": document["node_id"], "relationship": document.get("relationship"),
                  "relationship_basis": document.get("relationship_basis")}],
                node_id=document["node_id"], ecosystem=document.get("ecosystem"), version=document.get("version"),
                relationship=document.get("relationship"), vulnerable=vulnerable)


def vulnerability(target: str, advisory: dict[str, Any]) -> dict[str, Any]:
    others = advisory.get("match_count", 1) - 1
    return node(f"vuln:{target}:{advisory['group_key']}", VULNERABILITY, advisory["source_id"], OBSERVED,
                (advisory.get("summary") or "The advisory source lists the installed version as affected.")
                + (f" ({others} more record(s) describe the same vulnerability.)" if others > 0 else ""),
                [{"type": "advisory_match", "basis": OBSERVED, "ref": {"collection": "vulnerability_matches", "id": match_id}}
                 for match_id in advisory.get("match_ids", [])[:5]],
                severity=advisory.get("severity") or "UNKNOWN", aliases=advisory.get("aliases", [])[:10],
                fixed_versions=advisory.get("fixed_versions", [])[:10])


_REACHABILITY_TEXT = {
    "REACHABLE": "Static analysis found application code that refers to the affected functionality.",
    "NOT_CONFIRMED_REACHABLE": "Static analysis found no application code that refers to the affected functionality. This is not proof of absence.",
    "UNKNOWN": "Static analysis could not decide whether application code reaches the affected functionality.",
    "UNSUPPORTED": "The package's language is not supported by the reachability analysis; whether it is reached is unknown.",
    "NOT_ANALYSED": "No reachability analysis exists for this snapshot; whether the affected functionality is reached is unknown.",
}


def reachability(target: str, group_key: str, finding: dict[str, Any] | None, state: str) -> dict[str, Any]:
    evidence = []
    if finding is not None:
        located = finding.get("evidence") or {}
        evidence.append({"type": "reachability_finding", "basis": DERIVED, "ref": {"collection": "code_reachability", "id": finding.get("_id")},
                         "status": finding.get("status"), "reason": finding.get("reason"),
                         **{k: located.get(k) for k in ("source_file", "line", "symbol") if located.get(k) is not None}})
    return node(f"reach:{target}:{group_key}", REACHABILITY, state.replace("_", " ").title(), DERIVED if finding is not None else INFERRED,
                _REACHABILITY_TEXT[state], evidence, state=state)


def application(finding: dict[str, Any] | None, state: str) -> dict[str, Any]:
    located = (finding or {}).get("evidence") or {}
    source_file = located.get("source_file") if state == "REACHABLE" else None
    if source_file:
        line = located.get("line")
        return node(f"app:{source_file}", APPLICATION, source_file, OBSERVED,
                    f"Application code at {source_file}{f':{line}' if line else ''} refers to the affected functionality.",
                    [{"type": "source_location", "basis": OBSERVED, "source_file": source_file, "line": line, "symbol": located.get("symbol")}],
                    located=True)
    return node("app:unlocated", APPLICATION, "Application (use site not established)", INFERRED,
                "No application code location is tied to this path. The application is shown because it contains the dependency.",
                located=False)


def downstream(target: str, dependents: int, packages: int, exposes: list[str]) -> dict[str, Any]:
    label = f"{dependents} dependent package(s)" if dependents else "No dependent packages"
    return node(f"down:{target}", DOWNSTREAM_COMPONENT, label, DERIVED,
                f"{dependents} of {max(packages - 1, 0)} other packages in the graph depend on the affected package directly or through others.",
                [{"type": "graph_metric", "basis": DERIVED, "metric": "dependents", "value": dependents, "examples": exposes[:5]}],
                dependents=dependents)


def impact(target: str, advisory: dict[str, Any], state: str) -> dict[str, Any]:
    severity = advisory.get("severity") or "UNKNOWN"
    published = f"The advisory source publishes severity {severity}." if severity != "UNKNOWN" else "The advisory source publishes no severity."
    return node(f"impact:{target}:{advisory['group_key']}", IMPACT, "Potential impact", INFERRED,
                f"{published} What an attacker could achieve depends on how the application uses the package; "
                "it was not tested and is not established here.", severity=severity, exploit_confirmed=False, reachability_state=state)

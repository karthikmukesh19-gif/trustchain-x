"""Attack-path simulation: the search engine, confidence, scoring, the simulation itself, and the API end to end.

Graphs in the unit tests are built by hand. The end-to-end tests reuse the
dependency-intelligence fixture repository; GHSA-* records are real public
advisories, TEST-* records are synthetic. Nothing contacts the network and no
exploit or repository code is executed: the engine only reads stored data.
"""

import pytest

from app.analyzers.attack_paths import attack_edges as E
from app.analyzers.attack_paths import attack_nodes as N
from app.analyzers.attack_paths import risk
from app.analyzers.attack_paths.graph import AttackGraph, combine
from app.analyzers.attack_paths.path_engine import shortest_path, simple_paths
from app.analyzers.attack_paths.simulation import Inputs, Limits, choke_points, path_id, simulate, strongest_finding, without
from app.analyzers.graph.graph_metrics import analyse_structure
from app.models.collections import ANALYSIS_RUNS, ATTACK_PATHS
from tests.conftest import run_worker
from tests.test_intelligence import (  # noqa: F401 - fixtures
    advisories, analysed, get, packages, project, repo, settings, start, url,
)

# --- the search engine ------------------------------------------------------------------

GRAPH = {"a": ["b", "c"], "b": ["d"], "c": ["d"], "d": ["e"], "e": [], "x": ["a"]}


def successors(graph):
    return lambda node: graph.get(node, [])


def test_bfs_finds_the_shortest_path():
    assert shortest_path(successors(GRAPH), "a", lambda n: n == "e", max_depth=10) == ["a", "b", "d", "e"]


def test_bfs_start_is_goal():
    assert shortest_path(successors(GRAPH), "a", lambda n: n == "a", max_depth=0) == ["a"]


def test_bfs_respects_the_depth_limit():
    assert shortest_path(successors(GRAPH), "a", lambda n: n == "e", max_depth=2) is None
    assert shortest_path(successors(GRAPH), "a", lambda n: n == "e", max_depth=3) is not None


def test_bfs_returns_none_when_unreachable():
    assert shortest_path(successors(GRAPH), "e", lambda n: n == "a", max_depth=10) is None


def test_bfs_terminates_on_cycles():
    cyclic = {"a": ["b"], "b": ["c"], "c": ["a"]}
    assert shortest_path(successors(cyclic), "a", lambda n: n == "z", max_depth=50) is None


def test_bfs_stops_at_the_visit_limit():
    chain = {str(i): [str(i + 1)] for i in range(100)}
    assert shortest_path(successors(chain), "0", lambda n: n == "99", max_depth=200, max_visited=10) is None


def test_dfs_lists_every_simple_path():
    paths, truncated = simple_paths(successors(GRAPH), "a", lambda n: n == "e", max_depth=10, max_paths=10, max_expansions=1000)
    assert sorted(paths) == [["a", "b", "d", "e"], ["a", "c", "d", "e"]] and truncated is False


def test_dfs_never_repeats_a_node_on_a_path():
    cyclic = {"a": ["b"], "b": ["c", "a"], "c": ["a", "d"], "d": []}
    paths, truncated = simple_paths(successors(cyclic), "a", lambda n: n == "d", max_depth=10, max_paths=10, max_expansions=1000)
    assert paths == [["a", "b", "c", "d"]] and truncated is False


def test_dfs_depth_limit_is_reported():
    paths, truncated = simple_paths(successors(GRAPH), "a", lambda n: n == "e", max_depth=2, max_paths=10, max_expansions=1000)
    assert paths == [] and truncated is True


def test_dfs_path_limit_is_reported():
    paths, truncated = simple_paths(successors(GRAPH), "a", lambda n: n == "e", max_depth=10, max_paths=1, max_expansions=1000)
    assert len(paths) == 1 and truncated is True


def test_dfs_expansion_limit_is_reported():
    wide = {"s": [f"n{i}" for i in range(50)], **{f"n{i}": ["t"] for i in range(50)}, "t": []}
    paths, truncated = simple_paths(successors(wide), "s", lambda n: n == "t", max_depth=5, max_paths=1000, max_expansions=10)
    assert truncated is True and len(paths) < 50


def test_dfs_with_no_room_for_paths():
    assert simple_paths(successors(GRAPH), "a", lambda n: True, max_depth=5, max_paths=0, max_expansions=10) == ([], True)


def test_dfs_goal_at_start_and_continuing_through_goals():
    paths, _ = simple_paths(successors(GRAPH), "a", lambda n: n in ("a", "d"), max_depth=10, max_paths=10, max_expansions=100)
    assert sorted(paths) == [["a"], ["a", "b", "d"], ["a", "c", "d"]]


def test_dfs_survives_a_very_deep_graph_without_recursion():
    chain = {i: [i + 1] for i in range(5000)}
    paths, truncated = simple_paths(lambda n: chain.get(n, []), 0, lambda n: n == 5000, max_depth=6000, max_paths=1, max_expansions=10_000)
    assert len(paths) == 1 and len(paths[0]) == 5001 and truncated is True   # stopped by the path limit, not by a crash


# --- confidence and score ---------------------------------------------------------------

def test_confidence_is_the_product_of_the_steps_and_names_what_lowered_it():
    edges = [E.edge("a", "b", E.DECLARES, N.OBSERVED, 1.0, "r1"), E.edge("b", "c", E.AFFECTED_BY, N.OBSERVED, 0.8, "r2"),
             E.edge("c", "d", E.ASSESSED_AS, N.INFERRED, 0.5, "r3")]
    value, lowered = E.propagate(edges)
    assert value == 0.4 and [item["edge"] for item in lowered] == [E.AFFECTED_BY, E.ASSESSED_AS]


def test_confidence_is_clamped():
    assert E.edge("a", "b", E.REQUIRES, N.OBSERVED, 7, "x")["confidence"] == 1.0
    assert E.edge("a", "b", E.REQUIRES, N.OBSERVED, -1, "x")["confidence"] == 0.0


@pytest.mark.parametrize("basis,expected", [("OBSERVED", 1.0), ("INFERRED", 0.8), ("UNKNOWN", 0.6), (None, 0.6)])
def test_declaration_confidence_follows_how_the_relationship_is_known(basis, expected):
    assert E.declaration_confidence({"relationship_basis": basis}) == expected


@pytest.mark.parametrize("finding,state,expected", [
    ({"confidence": "HIGH"}, "REACHABLE", 1.0), ({"confidence": "MEDIUM"}, "REACHABLE", 0.8), ({"confidence": "LOW"}, "NOT_CONFIRMED_REACHABLE", 0.6),
    ({}, "REACHABLE", 0.7), ({"confidence": "HIGH"}, "UNKNOWN", 0.5), (None, "NOT_ANALYSED", 0.5), ({"confidence": "HIGH"}, "UNSUPPORTED", 0.5)])
def test_reachability_confidence(finding, state, expected):
    assert E.reachability_confidence(finding, state) == expected


@pytest.mark.parametrize("has_route,state,expected", [
    (True, "REACHABLE", risk.SUPPORTED_PATH), (True, "NOT_CONFIRMED_REACHABLE", risk.POTENTIAL_PATH), (True, "UNKNOWN", risk.UNKNOWN_PATH),
    (True, "UNSUPPORTED", risk.UNKNOWN_PATH), (True, "NOT_ANALYSED", risk.UNKNOWN_PATH), (False, "REACHABLE", risk.OBSERVED_COMPONENT)])
def test_status(has_route, state, expected):
    assert risk.status_for(has_route, state) == expected


def test_score_is_the_documented_product():
    impact = risk.graph_impact(1, 0, 10)
    assert impact == {"value": 0.7, "proximity": 1.0, "downstream": 0.0, "chain_length": 1, "dependents": 0}
    parts = risk.components("HIGH", "REACHABLE", impact, 1.0)
    assert risk.score(parts) == 56.0 and risk.level(56.0) == "HIGH"


def test_graph_impact_grows_with_dependents_and_shrinks_with_distance():
    assert risk.graph_impact(1, 10, 20)["value"] > risk.graph_impact(1, 0, 20)["value"]
    assert risk.graph_impact(1, 0, 20)["value"] > risk.graph_impact(4, 0, 20)["value"] > risk.graph_impact(None, 0, 20)["value"]
    assert risk.graph_impact(1, 500, 20)["value"] == 1.0


def test_no_reachability_state_scores_zero_and_unknown_severity_is_not_zero():
    impact = risk.graph_impact(1, 0, 10)
    for state in ("REACHABLE", "UNKNOWN", "UNSUPPORTED", "NOT_ANALYSED", "NOT_CONFIRMED_REACHABLE"):
        assert risk.score(risk.components("UNKNOWN", state, impact, 1.0)) > 0
    assert risk.components("nonsense", "REACHABLE", impact, 1.0)["severity"] == "UNKNOWN"


@pytest.mark.parametrize("value,expected", [(0, "LOW"), (19.9, "LOW"), (20, "MEDIUM"), (49.9, "MEDIUM"), (50, "HIGH"), (100, "HIGH")])
def test_levels(value, expected):
    assert risk.level(value) == expected


# --- the simulation ---------------------------------------------------------------------

def dep(node_id, relationship="TRANSITIVE", basis="OBSERVED"):
    ecosystem, rest = node_id.split(":")
    name, version = rest.split("@")
    return {"_id": f"id-{node_id}", "node_id": node_id, "name": name, "normalized_name": name, "ecosystem": ecosystem, "version": version,
            "relationship": relationship, "relationship_basis": basis, "relationship_reason": f"{name} is required",
            "evidence": [{"source_file": "package-lock.json", "line": 3, "declaration": f"{name} {version}"}]}


def adv(identifier, severity="HIGH", rank=3, fixed=("9.9.9",), confidence="HIGH"):
    return {"group_key": identifier, "source_id": identifier, "aliases": [], "severity": severity, "severity_rank": rank,
            "summary": f"Synthetic advisory {identifier}", "confidence": confidence, "fixed_versions": list(fixed), "match_ids": [f"m-{identifier}"],
            "match_count": 1, "match_explanation": "inside the affected range"}


def build(edges, advisories, findings=None, analysed=True, limits=Limits(), annotations=None, extra_nodes=()):
    ids = sorted({end for edge in edges for end in edge if end != "root"} | set(extra_nodes))
    structure = analyse_structure([{"node_id": i} for i in ids], [{"source": s, "target": t} for s, t in edges])
    direct = {t for s, t in edges if s == "root"}
    dependencies = {i: dep(i, "DIRECT" if i in direct else "TRANSITIVE") for i in ids}
    return simulate(Inputs(project_name="Demo", snapshot_id="snap1", structure=structure, dependencies=dependencies, advisories=advisories,
                           findings=findings or {}, reachability_analysed=analysed, annotations=annotations or {}), limits)


A, B, C, D = "npm:a@1.0.0", "npm:b@1.0.0", "npm:c@1.0.0", "npm:d@1.0.0"
DIAMOND = [("root", A), ("root", B), (A, C), (B, C), (C, D)]


def finding(status, confidence="HIGH", file="src/app.py", line=7):
    return {"_id": f"f-{status}", "status": status, "confidence": confidence, "reason": "PATH_FOUND",
            "evidence": {"source_file": file, "line": line, "symbol": "app:main"}}


def test_a_path_walks_every_stage_in_order():
    result = build(DIAMOND, {D: [adv("ADV-1")]}, {(D, "ADV-1"): [finding("REACHABLE")]})
    [path] = result["paths"]
    stages = [node["stage"] for node in path["nodes"]]
    assert stages == [N.ENTRY, N.DEPENDENCY, N.DEPENDENCY, N.DEPENDENCY, N.VULNERABILITY, N.REACHABILITY, N.APPLICATION,
                      N.DOWNSTREAM_COMPONENT, N.IMPACT]
    assert path["route"] == [A, C, D] and path["alternative_routes"] == [[B, C, D]] and path["route_length"] == 3
    # every edge joins consecutive nodes: the path is one chain
    assert [(e["source"], e["target"]) for e in path["edges"]] == list(zip([n["id"] for n in path["nodes"]], [n["id"] for n in path["nodes"]][1:]))


def test_a_supported_path_needs_a_reachable_finding():
    path = build(DIAMOND, {D: [adv("ADV-1")]}, {(D, "ADV-1"): [finding("REACHABLE")]})["paths"][0]
    assert path["status"] == risk.SUPPORTED_PATH and path["reachability"] == {"state": "REACHABLE", "finding_id": "f-REACHABLE",
                                                                              "source_file": "src/app.py", "line": 7}
    assert path["confidence"] == 1.0 and path["components"]["confidence_lowered_by"] == []
    application = next(n for n in path["nodes"] if n["stage"] == N.APPLICATION)
    assert application["label"] == "src/app.py" and application["basis"] == N.OBSERVED


@pytest.mark.parametrize("status,expected,located", [
    ("NOT_CONFIRMED_REACHABLE", risk.POTENTIAL_PATH, False), ("UNKNOWN", risk.UNKNOWN_PATH, False), ("UNSUPPORTED", risk.UNKNOWN_PATH, False)])
def test_paths_without_reachable_evidence_are_not_supported(status, expected, located):
    path = build(DIAMOND, {D: [adv("ADV-1")]}, {(D, "ADV-1"): [finding(status)]})["paths"][0]
    assert path["status"] == expected and path["reachability"]["source_file"] is None
    application = next(n for n in path["nodes"] if n["stage"] == N.APPLICATION)
    assert application["located"] is located and application["basis"] == N.INFERRED


def test_without_a_reachability_analysis_the_path_is_unknown_not_safe():
    path = build(DIAMOND, {D: [adv("ADV-1")]}, {(D, "ADV-1"): [finding("REACHABLE")]}, analysed=False)["paths"][0]
    assert path["status"] == risk.UNKNOWN_PATH and path["reachability"]["state"] == "NOT_ANALYSED" and path["score"] > 0
    assert path["confidence"] == 0.5
    assert {"edge": E.ASSESSED_AS, "confidence": 0.5} == {k: path["components"]["confidence_lowered_by"][0][k] for k in ("edge", "confidence")}


def test_a_vulnerable_package_with_no_chain_is_an_observed_component():
    result = build([("root", A)], {D: [adv("ADV-1")]}, extra_nodes=[D])
    [path] = result["paths"]
    assert path["status"] == risk.OBSERVED_COMPONENT and path["route"] is None and path["nodes"][0]["stage"] == N.DEPENDENCY
    assert path["components"]["graph_impact_detail"]["proximity"] == 0.0 and "no chain" in path["explanation"][0]["text"]


def test_advisories_for_packages_outside_the_graph_produce_no_path():
    assert build(DIAMOND, {"npm:ghost@1.0.0": [adv("ADV-1")]})["paths"] == []


def test_one_path_per_distinct_vulnerability_ordered_by_score():
    result = build(DIAMOND, {D: [adv("ADV-LOW", "LOW", 1), adv("ADV-CRIT", "CRITICAL", 4)], A: [adv("ADV-A", "MEDIUM", 2)]})
    assert [p["advisory"]["source_id"] for p in result["paths"]] == ["ADV-CRIT", "ADV-A", "ADV-LOW"]
    assert [p["rank"] for p in result["paths"]] == [1, 2, 3]
    assert result["summary"]["paths"] == 3 and result["summary"]["vulnerable_packages"] == 2
    assert result["summary"]["by_severity"] == {"CRITICAL": 1, "MEDIUM": 1, "LOW": 1}


def test_the_result_is_deterministic():
    arguments = (DIAMOND, {D: [adv("ADV-2"), adv("ADV-1")], C: [adv("ADV-3", "UNKNOWN", 0)]}, {(D, "ADV-1"): [finding("UNKNOWN"), finding("REACHABLE")]})
    assert build(*arguments) == build(*arguments)


def test_path_ids_are_stable_and_distinct():
    assert path_id("s", "n", "g") == path_id("s", "n", "g") and len(path_id("s", "n", "g")) == 24
    assert len({path_id("s", "n", "g"), path_id("s2", "n", "g"), path_id("s", "n2", "g"), path_id("s", "n", "g2")}) == 4


def test_the_strongest_finding_decides_the_state():
    assert strongest_finding([finding("NOT_CONFIRMED_REACHABLE"), finding("REACHABLE")], True)[1] == "REACHABLE"
    assert strongest_finding([finding("NOT_CONFIRMED_REACHABLE"), finding("UNKNOWN")], True)[1] == "UNKNOWN"
    assert strongest_finding([], True) == (None, "NOT_ANALYSED") and strongest_finding([finding("REACHABLE")], False) == (None, "NOT_ANALYSED")
    assert strongest_finding([{"status": "SOMETHING_ELSE"}], True) == (None, "NOT_ANALYSED")


def test_cycles_in_the_dependency_graph_do_not_trap_the_search():
    result = build([("root", A), (A, B), (B, C), (C, A), (C, D)], {D: [adv("ADV-1")]})
    assert result["paths"][0]["route"] == [A, B, C, D]


def test_the_path_limit_keeps_the_highest_scores_and_is_reported():
    advisories = {D: [adv(f"ADV-{n}", "LOW" if n else "CRITICAL", 1 if n else 4) for n in range(6)]}
    result = build(DIAMOND, advisories, limits=Limits(max_paths=2))
    assert len(result["paths"]) == 2 and result["paths"][0]["advisory"]["source_id"] == "ADV-0"
    assert result["summary"]["paths_truncated"] is True and result["summary"]["candidates"] == 6


def test_a_chain_longer_than_the_depth_limit_is_shortened_not_lost():
    ids = [f"npm:p{n}@1.0.0" for n in range(10)]
    edges = [("root", ids[0]), *zip(ids, ids[1:])]
    path = build(edges, {ids[-1]: [adv("ADV-1")]}, limits=Limits(max_depth=4))["paths"][0]
    assert path["route"] == [ids[0], ids[1], ids[8], ids[9]] and path["route_omitted"] == 6 and path["route_length"] == 10
    assert path["routes_truncated"] is True and path["status"] == risk.UNKNOWN_PATH
    assert any("left out" in e["reason"] for e in path["edges"])
    assert path["components"]["graph_impact_detail"]["chain_length"] == 10


def test_route_limit_of_one_lists_no_alternatives():
    path = build(DIAMOND, {D: [adv("ADV-1")]}, limits=Limits(max_routes=1))["paths"][0]
    assert path["alternative_routes"] == []


def test_alternative_routes_beyond_the_limit_are_reported_as_truncated():
    middle = [f"npm:m{n}@1.0.0" for n in range(6)]
    edges = [("root", m) for m in middle] + [(m, D) for m in middle]
    path = build(edges, {D: [adv("ADV-1")]}, limits=Limits(max_routes=3))["paths"][0]
    assert len(path["alternative_routes"]) == 2 and path["routes_truncated"] is True


def test_every_path_carries_evidence_and_an_explanation_and_never_confirms_an_exploit():
    result = build(DIAMOND, {D: [adv("ADV-1")]}, {(D, "ADV-1"): [finding("REACHABLE")]})
    path = result["paths"][0]
    assert {item["type"] for item in path["evidence"]} >= {"dependency_declaration", "dependency", "advisory_match", "reachability_finding",
                                                           "source_location", "graph_metric"}
    assert all(item["basis"] in (N.OBSERVED, N.DERIVED) for item in path["evidence"])
    assert {line["basis"] for line in path["explanation"]} == {N.OBSERVED, N.DERIVED, N.INFERRED}
    assert path["exploit_confirmed"] is False and result["summary"]["exploit_confirmed"] == 0
    impact = path["nodes"][-1]
    assert impact["exploit_confirmed"] is False and impact["basis"] == N.INFERRED and "not established" in impact["detail"]
    text = " ".join(line["text"] for line in path["explanation"]).lower()
    assert "no exploit was attempted" in text and "exploit confirmed" not in text


def test_low_confidence_inputs_lower_the_path():
    low = build(DIAMOND, {D: [adv("ADV-1", confidence="LOW")]}, {(D, "ADV-1"): [finding("REACHABLE", "MEDIUM")]})["paths"][0]
    assert low["confidence"] == 0.48 and len(low["components"]["confidence_lowered_by"]) == 2


def test_break_points_are_recommendations():
    path = build(DIAMOND, {D: [adv("ADV-1")]})["paths"][0]
    assert [p["action"] for p in path["break_points"]] == ["UPGRADE", "REVIEW_PARENT"] and all(p["basis"] == "RECOMMENDED" for p in path["break_points"])
    no_fix = build([("root", A)], {A: [adv("ADV-1", fixed=())]})["paths"][0]
    assert [p["action"] for p in no_fix["break_points"]] == ["REVIEW"]


def test_scores_from_dependency_intelligence_are_attached_as_related_not_mixed_in():
    plain = build(DIAMOND, {D: [adv("ADV-1")]})["paths"][0]
    annotated = build(DIAMOND, {D: [adv("ADV-1")]}, annotations={D: {"predictive_risk": 80, "basis": "PREDICTED"}})["paths"][0]
    assert annotated["related"] == {"predictive_risk": 80, "basis": "PREDICTED"} and plain["related"] is None
    assert annotated["score"] == plain["score"]


def test_choke_points_rank_packages_by_paths_through_them():
    result = build(DIAMOND, {D: [adv("ADV-1"), adv("ADV-2")], C: [adv("ADV-3")]})
    points = choke_points(result["paths"])
    assert points[0]["node_id"] in (A, C) and {p["node_id"]: p["paths"] for p in points} == {A: 3, C: 3, D: 2}
    assert next(p for p in points if p["node_id"] == D)["is_target"] is True


def test_what_if_removes_paths_only_when_every_chain_passes_through_the_package():
    result = build(DIAMOND, {D: [adv("ADV-1")], C: [adv("ADV-2")]})
    assert without(result["paths"], D)["paths_removed"] == 1
    assert without(result["paths"], C)["paths_removed"] == 2          # C is on every chain to D, and is itself a target
    through_a = without(result["paths"], A)                          # B still leads to C and D
    assert through_a["paths_removed"] == 0 and through_a["paths_remaining"] == 2
    assert without(result["paths"], "npm:nothing@1")["paths_removed"] == 0


def test_what_if_does_not_conclude_removal_from_truncated_alternatives():
    middle = [f"npm:m{n}@1.0.0" for n in range(6)]
    edges = [("root", A)] + [(A, m) for m in middle] + [(m, D) for m in middle]
    result = build(edges, {D: [adv("ADV-1")]}, limits=Limits(max_routes=2))
    outcome = without(result["paths"], A)
    assert outcome["paths_removed"] == 0 and outcome["paths_undetermined"] == 1 and outcome["highest_score_after"] == outcome["highest_score_before"]


def test_the_combined_graph_merges_shared_nodes_and_counts_paths():
    result = build(DIAMOND, {D: [adv("ADV-1"), adv("ADV-2")]})
    merged = combine(result["paths"], 100)
    by_id = {node["id"]: node for node in merged["nodes"]}
    assert by_id[f"dep:{D}"]["paths"] == 2 and by_id[f"dep:{D}"]["vulnerable"] is True and by_id["entry:project"]["paths"] == 2
    assert merged["truncated"] is False and merged["paths_included"] == 2 and merged["paths_total"] == 2
    assert all("evidence" not in node for node in merged["nodes"])
    assert [node["stage"] for node in merged["nodes"]] == sorted((node["stage"] for node in merged["nodes"]), key=N.STAGES.index)


def test_the_combined_graph_adds_whole_paths_or_nothing():
    result = build(DIAMOND, {D: [adv("ADV-1", "CRITICAL", 4)], A: [adv("ADV-2", "LOW", 1)]})
    merged = combine(result["paths"], 9)
    assert merged["truncated"] is True and merged["paths_included"] == 1 and len(merged["nodes"]) == 9
    graph = AttackGraph(100, 2)
    assert graph.add_path(result["paths"][0]) is False and graph.nodes == {} and graph.truncated is True


# --- end to end -------------------------------------------------------------------------

@pytest.fixture
def simulated(client, app, auth_headers, project):
    job = start(client, app, auth_headers, project, "/attack-paths/analyze")
    assert job["state"] == "completed", job
    return project


def test_analysis_needs_a_snapshot_and_a_vulnerability_check(client, app, auth_headers, analysed):
    created = client.post("/api/projects", json={"name": "Empty", "repository_url": "https://github.com/octo/other"}, headers=auth_headers).json()
    assert client.post(url(created, "/attack-paths/analyze"), headers=auth_headers).status_code == 409
    response = client.post(url(analysed, "/attack-paths/analyze"), headers=auth_headers)
    assert response.status_code == 409 and "vulnerability check" in response.json()["detail"]


def test_before_any_analysis_nothing_is_reported(client, auth_headers, project):
    body = get(client, auth_headers, project, "/attack-paths")
    assert body["analysis"] is None and body["items"] == [] and body["total"] == 0 and body["has_vulnerability_scan"] is True
    assert client.get(url(project, "/attack-paths/graph"), headers=auth_headers).status_code == 404
    assert client.get(url(project, "/attack-paths/" + "0" * 24), headers=auth_headers).status_code == 404


def test_paths_are_built_from_the_stored_matches(client, auth_headers, simulated, db):
    body = get(client, auth_headers, simulated, "/attack-paths")
    assert body["total"] == 7 == db[ATTACK_PATHS].count_documents({})        # one per distinct vulnerability per package
    assert body["analysis"]["model_version"] == "attack-path-v1" and body["analysis"]["summary"]["exploit_confirmed"] == 0
    # No reachability analysis was run: nothing may be called supported.
    assert body["analysis"]["summary"]["by_status"] == {"SUPPORTED_PATH": 0, "POTENTIAL_PATH": 0, "UNKNOWN_PATH": 7, "OBSERVED_COMPONENT": 0}
    scores = [item["score"] for item in body["items"]]
    assert scores == sorted(scores, reverse=True) and all(0 < score <= 100 for score in scores)
    assert "nodes" not in body["items"][0] and "project_id" not in body["items"][0]
    assert {item["target"]["node_id"] for item in body["items"]} == {"pypi:requests@2.19.1", "npm:lodash@4.17.20", "npm:ms@2.0.0", "npm:qs@6.7.0"}


def test_reachability_evidence_turns_a_path_into_a_supported_one(client, app, auth_headers, project):
    assert start(client, app, auth_headers, project, "/code-reachability/analyze")["state"] == "completed"
    assert start(client, app, auth_headers, project, "/attack-paths/analyze")["state"] == "completed"
    body = get(client, auth_headers, project, "/attack-paths", status="SUPPORTED_PATH")
    assert [item["advisory"]["source_id"] for item in body["items"]] == ["TEST-REQ-GET"]
    detail = get(client, auth_headers, project, "/attack-paths/" + body["items"][0]["attack_path_id"])
    assert detail["reachability"] == {"state": "REACHABLE", "finding_id": detail["reachability"]["finding_id"], "source_file": "app/client.py", "line": 5}
    assert [node["stage"] for node in detail["nodes"]] == ["ENTRY", "DEPENDENCY", "VULNERABILITY", "REACHABILITY", "APPLICATION",
                                                           "DOWNSTREAM_COMPONENT", "IMPACT"]
    assert detail["exploit_confirmed"] is False and detail["evidence"] and detail["explanation"]
    # npm packages are outside the reachability analysis: their paths stay unknown, not potential and not safe.
    unknown = get(client, auth_headers, project, "/attack-paths", status="UNKNOWN_PATH")
    assert unknown["total"] == 6


def test_transitive_paths_follow_the_lockfile_chain(client, auth_headers, simulated):
    item = get(client, auth_headers, simulated, "/attack-paths", q="TEST-MS-1")["items"][0]
    assert item["route"][-1] == "npm:ms@2.0.0" and item["route"][-2] == "npm:debug@2.6.9" and item["route_length"] == 3
    assert item["alternative_routes"] and item["downstream"]["dependents"] >= 3


def test_filters_and_validation(client, auth_headers, simulated):
    assert get(client, auth_headers, simulated, "/attack-paths", severity="HIGH")["total"] == 2
    assert get(client, auth_headers, simulated, "/attack-paths", q="qs")["total"] == 3
    assert get(client, auth_headers, simulated, "/attack-paths", q=".*")["total"] == 0          # a search is text, never a pattern
    assert get(client, auth_headers, simulated, "/attack-paths", limit=2, skip=6)["items"].__len__() == 1
    low = get(client, auth_headers, simulated, "/attack-paths", level="LOW")["total"]
    assert low + get(client, auth_headers, simulated, "/attack-paths", level="MEDIUM")["total"] \
        + get(client, auth_headers, simulated, "/attack-paths", level="HIGH")["total"] == 7
    for params in ({"status": "CONFIRMED"}, {"level": "EXTREME"}, {"severity": "BAD"}, {"limit": 0}, {"skip": -1}):
        assert client.get(url(simulated, "/attack-paths"), headers=auth_headers, params=params).status_code == 422


def test_graph_view_and_what_if(client, auth_headers, simulated):
    body = get(client, auth_headers, simulated, "/attack-paths/graph")
    assert body["paths_total"] == 7 and body["paths_included"] == 7 and body["truncated"] is False and body["what_if"] is None
    ids = {node["id"] for node in body["nodes"]}
    assert "entry:project" in ids and all(edge["source"] in ids and edge["target"] in ids for edge in body["edges"])
    assert body["choke_points"][0]["paths"] >= 3
    what_if = get(client, auth_headers, simulated, "/attack-paths/graph", without="npm:qs@6.7.0")["what_if"]
    assert what_if["paths_removed"] == 3 and what_if["paths_remaining"] == 4 and what_if["basis"] == "DERIVED"


@pytest.mark.parametrize("settings", [{"ATTACK_PATH_GRAPH_MAX_NODES": "12"}], indirect=True)
def test_graph_view_respects_its_node_limit(client, auth_headers, simulated):
    body = get(client, auth_headers, simulated, "/attack-paths/graph")
    assert body["truncated"] is True and len(body["nodes"]) <= 12 and 0 < body["paths_included"] < 7


@pytest.mark.parametrize("settings", [{"ATTACK_PATH_MAX_PATHS": "3"}], indirect=True)
def test_path_limit_setting_is_applied(client, auth_headers, simulated):
    body = get(client, auth_headers, simulated, "/attack-paths")
    assert body["total"] == 3 and body["analysis"]["summary"]["paths_truncated"] is True


def test_an_unchanged_input_reuses_the_analysis_and_a_changed_one_does_not(client, app, auth_headers, simulated, db):
    again = start(client, app, auth_headers, simulated, "/attack-paths/analyze")
    assert again["state"] == "completed" and again["summary"]["reused"] is True and db[ANALYSIS_RUNS].count_documents({}) == 1
    assert start(client, app, auth_headers, simulated, "/code-reachability/analyze")["state"] == "completed"
    fresh = start(client, app, auth_headers, simulated, "/attack-paths/analyze")
    assert fresh["summary"]["reused"] is False and db[ANALYSIS_RUNS].count_documents({}) == 2
    history = get(client, auth_headers, simulated, "/attack-paths/history")["items"]
    assert len(history) == 2 and "input_digest" not in history[0] and history[0]["created_at"] >= history[1]["created_at"]
    # the list reads the newest analysis only
    assert get(client, auth_headers, simulated, "/attack-paths")["total"] == 7


def test_path_ids_must_be_well_formed(client, auth_headers, simulated):
    for bad in ("abc", "Z" * 24, "0" * 25, "..%2F..", "{'$ne': 1}"):
        assert client.get(url(simulated, f"/attack-paths/{bad}"), headers=auth_headers).status_code == 404


def test_other_users_cannot_see_or_start_anything(client, other_headers, auth_headers, simulated):
    path = get(client, auth_headers, simulated, "/attack-paths")["items"][0]["attack_path_id"]
    for method, path_ in (("post", "/attack-paths/analyze"), ("get", "/attack-paths"), ("get", "/attack-paths/graph"),
                          ("get", "/attack-paths/history"), ("get", f"/attack-paths/{path}")):
        assert getattr(client, method)(url(simulated, path_), headers=other_headers).status_code == 404
        assert getattr(client, method)(url(simulated, path_)).status_code == 401


def test_unknown_request_fields_are_rejected_and_a_running_job_blocks_another(client, auth_headers, project):
    assert client.post(url(project, "/attack-paths/analyze"), headers=auth_headers, json={"exploit": True}).status_code == 422
    assert client.post(url(project, "/attack-paths/analyze"), headers=auth_headers).status_code == 202
    assert client.post(url(project, "/attack-paths/analyze"), headers=auth_headers).status_code == 409


def test_a_new_snapshot_hides_the_old_paths(client, app, auth_headers, simulated, repo):
    repo.files["requirements.txt"] = b"requests==2.19.1\nPyYAML==5.1\nflask==3.0.0\n"
    assert start(client, app, auth_headers, simulated, "/analysis/dependencies")["state"] == "completed"
    body = get(client, auth_headers, simulated, "/attack-paths")
    assert body["analysis"] is None and body["items"] == [] and body["has_vulnerability_scan"] is False


def test_the_job_fails_cleanly_when_the_scan_is_out_of_date(client, app, auth_headers, simulated, repo, db):
    from app.services import jobs

    repo.files["requirements.txt"] = b"requests==2.19.1\n"
    assert start(client, app, auth_headers, simulated, "/analysis/dependencies")["state"] == "completed"
    stored = db["projects"].find_one({})
    jobs.request_job(db, app.state.redis, stored, jobs.ATTACK_PATH_ANALYSIS)
    assert run_worker(app) == 1
    job = client.get(url(simulated, "/jobs"), headers=auth_headers).json()["items"][0]
    assert job["state"] == "failed" and job["error"]["code"] == "NOT_SCANNED"


def test_deleting_the_project_removes_its_paths_and_runs(client, auth_headers, simulated, db):
    assert db[ATTACK_PATHS].count_documents({}) and db[ANALYSIS_RUNS].count_documents({})
    assert client.delete(f"/api/projects/{simulated['id']}", headers=auth_headers).status_code == 204
    assert db[ATTACK_PATHS].count_documents({}) == 0 and db[ANALYSIS_RUNS].count_documents({}) == 0


def test_the_audit_log_records_the_request_and_the_outcome(client, auth_headers, simulated, db):
    actions = [entry["action"] for entry in db["audit_logs"].find({"action": {"$regex": "attack_path"}})]
    assert actions == ["job.attack_path_analysis.request", "job.attack_path_analysis.finish"]

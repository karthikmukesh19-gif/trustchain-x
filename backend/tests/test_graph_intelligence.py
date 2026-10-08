"""Graph metrics, centrality, version risk, fragility, risk propagation, indicators and predictive risk (pure functions)."""

import random
import time
from datetime import datetime, timedelta, timezone

import pytest

from app.analyzers.fragility import MODEL_VERSION, DependencyFragilityAnalyzer, concentration, health, metrics, version_risk
from app.analyzers.fragility.fragility import WEIGHTS, FragilityInputs, level
from app.analyzers.graph import centrality, graph_metrics, prediction, risk_propagation
from app.analyzers.graph.graph_metrics import GraphLimits, GraphTooLarge, analyse_structure, build_model
from app.analyzers.vulnerabilities.versions import UnsupportedVersion, release_components

AS_OF = datetime(2026, 1, 1, tzinfo=timezone.utc)


def day(text):
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc)


def graph(edges, extra=()):
    names = sorted({name for edge in edges for name in edge if name != "root"} | set(extra))
    return [{"node_id": name} for name in names], [{"source": a, "target": b} for a, b in edges]


def structure(edges, extra=(), **limits):
    return analyse_structure(*graph(edges, extra), GraphLimits(**limits) if limits else GraphLimits())


def rows(edges, extra=()):
    return structure(edges, extra).rows


def dependency(node_id, version="1.0.0", ecosystem="npm", relationship="DIRECT"):
    name = node_id
    return {"_id": f"id-{node_id}", "node_id": node_id, "name": name, "normalized_name": name, "ecosystem": ecosystem, "version": version,
            "relationship": relationship}


def meta(latest, releases, status="COLLECTED", detail="FULL", **extra):
    return {"status": status, "detail": detail, "latest_version": latest, "latest_published_at": releases.get(latest) if latest else None,
            "versions": releases, "withdrawn_versions": [], "registry": "npm", **extra}


def analyse(edges, *, versions=None, metadata=None, vulnerabilities=None, reachability=None, analysed=False, extra=(), ecosystem="npm"):
    built = structure(edges, extra)
    dependencies = [dependency(node_id, (versions or {}).get(node_id, "1.0.0"), ecosystem,
                               "DIRECT" if built.rows[node_id]["direct"] else "TRANSITIVE") for node_id in built.model.ids]
    inputs = FragilityInputs(dependencies=dependencies, structure=built,
                             metadata={(ecosystem, name): value for name, value in (metadata or {}).items()},
                             vulnerabilities=vulnerabilities or {}, reachability=reachability or {}, reachability_analysed=analysed,
                             application_modules=10 if analysed else None, as_of=AS_OF)
    fragility = {row["node_id"]: row for row in DependencyFragilityAnalyzer().analyze(inputs)}
    risk = risk_propagation.propagate(built, vulnerabilities or {}, reachability or {}, analysed)
    return built, fragility, risk


def predict(edges, node, **options):
    built, fragility, risk = analyse(edges, **options)
    vulnerable = (options.get("vulnerabilities") or {}).get(node, {})
    reach = (options.get("reachability") or {}).get(node, {})
    found = prediction.indicators(fragility[node], risk["nodes"][node], vulnerable, reach, built.model.size, built.betweenness_computed)
    predicted = prediction.predictive_risk(fragility[node], risk["nodes"][node], built.model.size)
    return fragility[node], risk["nodes"][node], found, predicted


def vuln(distinct=1, severity="HIGH", advisories=("GHSA-test-0001",), fixed=("2.0.0",)):
    return {"matches": distinct, "distinct": distinct, "max_severity": severity, "by_severity": {severity: distinct},
            "advisories": list(advisories), "fixed_versions": list(fixed)}


def reach(status, **extra):
    key = {"REACHABLE": "reachable", "NOT_CONFIRMED_REACHABLE": "not_confirmed", "UNKNOWN": "unknown", "UNSUPPORTED": "unsupported"}[status]
    summary = {"findings": 1, "reachable": 0, "not_confirmed": 0, "unknown": 0, "unsupported": 0, "reachable_findings": [],
               "importing_modules": None, "use_sites": None, **extra}
    summary[key] = 1
    if status == "REACHABLE":
        summary["reachable_findings"] = [{"advisory_id": "GHSA-test-0001", "confidence": "HIGH", "source_file": "app/client.py", "line": 5}]
    return summary


CHAIN = [("root", "a"), ("a", "b"), ("b", "c"), ("c", "d")]
DIAMOND = [("root", "a"), ("root", "b"), ("a", "shared"), ("b", "shared"), ("shared", "leaf")]


# --- graph metrics ------------------------------------------------------------------------

def test_fan_in_fan_out_and_depth():
    found = rows(DIAMOND)
    assert (found["shared"]["fan_in"], found["shared"]["fan_out"], found["shared"]["depth"], found["shared"]["direct"]) == (2, 1, 2, False)
    assert (found["a"]["fan_in"], found["a"]["fan_out"], found["a"]["depth"], found["a"]["direct"]) == (0, 1, 1, True)
    assert (found["leaf"]["fan_in"], found["leaf"]["fan_out"], found["leaf"]["depth"]) == (1, 0, 3)


def test_dependents_and_introduced_follow_the_whole_chain():
    found = rows(CHAIN)
    assert [found[n]["dependents"] for n in "abcd"] == [0, 1, 2, 3]            # everything above it depends on it
    assert [found[n]["introduced"] for n in "abcd"] == [3, 2, 1, 0]            # everything below it is brought in by it
    assert found["d"]["dependents_share"] == 1.0 and found["a"]["dependents_share"] == 0.0


def test_duplicate_edges_and_self_loops_are_not_counted():
    once = structure([("root", "app"), ("app", "requests")])
    repeated = structure([("root", "app"), ("app", "requests"), ("app", "requests"), ("app", "requests"), ("app", "requests"), ("requests", "requests")])
    assert repeated.rows["requests"]["fan_in"] == once.rows["requests"]["fan_in"] == 1
    assert repeated.rows == once.rows
    assert repeated.model.issues == {"duplicate_edges": 3, "self_loops": 1} and once.model.issues == {}


def test_cycles_are_handled_and_reported():
    found = rows([("root", "a"), ("a", "b"), ("b", "c"), ("c", "a"), ("c", "d")])
    assert all(found[n]["in_cycle"] for n in "abc") and not found["d"]["in_cycle"]
    assert [found[n]["dependents"] for n in "abcd"] == [2, 2, 2, 3] and [found[n]["introduced"] for n in "abcd"] == [3, 3, 3, 0]
    assert [found[n]["depth"] for n in "abcd"] == [1, 2, 3, 4]


def test_disconnected_packages_keep_an_unknown_depth_and_are_never_linked():
    built = structure([("root", "a"), ("x", "y")], extra=["lonely"])
    assert built.rows["lonely"] == {**built.rows["lonely"], "depth": None, "connected_to_project": False, "fan_in": 0, "dependents": 0}
    assert built.rows["y"]["depth"] is None and built.rows["y"]["fan_in"] == 1 and built.rows["y"]["reached_by_direct"] == 0
    assert built.concentration["unconnected_packages"] == 3


def test_exclusive_counts_what_is_present_only_through_a_package():
    found = rows([("root", "a"), ("root", "b"), ("a", "only_a"), ("only_a", "deep"), ("a", "shared"), ("b", "shared")])
    assert found["a"]["exclusive"] == 2 and found["b"]["exclusive"] == 0 and found["shared"]["exclusive"] == 0
    assert found["a"]["introduced"] == 3


def test_reached_by_direct_counts_the_direct_dependencies_that_lead_to_a_package():
    found = rows([("root", f"d{i}") for i in range(4)] + [(f"d{i}", "core") for i in range(3)])
    assert (found["core"]["reached_by_direct"], found["core"]["reached_by_direct_share"]) == (3, 0.75)
    assert found["d0"]["reached_by_direct"] == 1                                # a direct dependency leads to itself


@pytest.mark.parametrize("nodes,edges", [
    ("not a list", []), ([None, 5, {}, {"node_id": 7}, {"node_id": ""}, {"node_id": "root"}, {"node_id": "ok"}, {"node_id": "ok"}], "junk"),
    ([{"node_id": "a"}], [None, {}, {"source": "a"}, {"source": 1, "target": 2}, {"source": "ghost", "target": "a"}, {"source": "a", "target": "ghost"}]),
])
def test_malformed_graphs_are_counted_not_trusted(nodes, edges):
    model = build_model(nodes, edges)
    assert model.size <= 1 and model.edge_count == 0
    assert graph_metrics.node_metrics(model) is not None


def test_malformed_parts_are_reported_by_kind():
    model = build_model([{"node_id": "a"}, {"node_id": "a"}, {"x": 1}],
                        [{"source": "root", "target": "a"}, {"source": "a", "target": "missing"}, "junk", {"source": "a", "target": "a"}])
    assert model.issues == {"nodes_without_id": 1, "duplicate_nodes": 1, "edges_malformed": 1, "edges_unknown_endpoint": 1, "self_loops": 1}


def test_graph_size_limits_are_enforced():
    nodes, edges = graph([("root", "a")] + [("a", f"n{i}") for i in range(20)])
    with pytest.raises(GraphTooLarge, match="21 packages; the limit is 10"):
        build_model(nodes, edges, GraphLimits(max_nodes=10, max_edges=100))
    with pytest.raises(GraphTooLarge, match="relationships"):
        build_model(nodes, edges, GraphLimits(max_nodes=100, max_edges=5))


def test_a_large_graph_is_analysed_quickly_and_deep_chains_do_not_overflow():
    random.seed(7)
    edges = [("root", f"n{i}") for i in range(40)] + [(f"n{random.randrange(i)}", f"n{i}") for i in range(40, 3000)]
    edges += [(f"n{random.randrange(3000)}", f"n{random.randrange(3000)}") for _ in range(6000)]
    started = time.monotonic()
    built = structure(edges)
    assert time.monotonic() - started < 20 and built.model.size == 3000 and not built.betweenness_computed
    deep = structure([("root", "n0")] + [(f"n{i}", f"n{i + 1}") for i in range(4000)])
    assert deep.rows["n4000"]["depth"] == 4001 and deep.rows["n4000"]["dependents"] == 4000


def test_metrics_agree_with_a_brute_force_computation():
    for seed in range(60):
        random.seed(seed)
        count = 9
        edges = [("root", f"n{random.randrange(count)}") for _ in range(2)] + \
                [(f"n{random.randrange(count)}", f"n{random.randrange(count)}") for _ in range(14)]
        found = rows(edges, extra=[f"n{i}" for i in range(count)])
        children = {}
        for source, target in edges:
            if source != target:
                children.setdefault(source, set()).add(target)

        def reachable(start, without=None):
            seen, stack = set(), [start]
            while stack:
                for target in children.get(stack.pop(), ()):
                    if target not in seen and target != without:
                        seen.add(target)
                        stack.append(target)
            return seen
        everything = reachable("root")
        for index in range(count):
            name = f"n{index}"
            assert found[name]["introduced"] == len(reachable(name) - {name}), (seed, name)
            assert found[name]["dependents"] == sum(1 for j in range(count) if j != index and name in reachable(f"n{j}")), (seed, name)
            assert found[name]["exclusive"] == (len(everything - reachable("root", name) - {name}) if name in everything else 0), (seed, name)
            assert found[name]["connected_to_project"] == (name in everything)


# --- centrality and concentration ---------------------------------------------------------

def test_degree_and_betweenness_centrality():
    built = structure(CHAIN)
    assert [built.rows[n]["degree_centrality"] for n in "abcd"] == [round(1 / 3, 6), round(2 / 3, 6), round(2 / 3, 6), round(1 / 3, 6)]
    # a->b->c->d: b lies on a->c and a->d, c on a->d and b->d; normalised by (n-1)(n-2) = 6.
    assert [built.rows[n]["betweenness_centrality"] for n in "abcd"] == [0.0, round(2 / 6, 6), round(2 / 6, 6), 0.0]
    assert built.rows["b"]["relative_centrality"] == 1.0 and built.rows["b"]["centrality_measure"] == "betweenness"


def test_the_hub_of_a_graph_is_its_most_central_package():
    edges = [("root", f"d{i}") for i in range(5)] + [(f"d{i}", "hub") for i in range(5)] + [("hub", f"leaf{i}") for i in range(5)]
    built = structure(edges)
    assert max(built.rows.values(), key=lambda r: r["betweenness_centrality"])["node_id"] == "hub"
    assert built.rows["hub"]["relative_centrality"] == 1.0 and built.rows["leaf0"]["relative_centrality"] == 0.0


def test_betweenness_is_skipped_above_the_work_limit_and_degree_is_used_instead():
    model = build_model(*graph(DIAMOND))
    assert centrality.betweenness(model, max_work=1) is None
    assert centrality.degree(build_model([], [])) == [] and centrality.degree(build_model([{"node_id": "a"}], [])) == [0.0]


def test_project_concentration_summarises_where_the_graph_converges():
    edges = [("root", f"d{i}") for i in range(4)] + [(f"d{i}", "core") for i in range(4)] + [("core", "base")]
    summary = structure(edges).concentration
    assert (summary["packages"], summary["direct_dependencies"], summary["max_depth"], summary["packages_in_cycles"]) == (6, 4, 3, 0)
    assert summary["top_dependents"][0] == {"node_id": "base", "dependents": 5, "share": 1.0}
    assert summary["top_dependents"][1]["node_id"] == "core" and summary["fan_in_hhi"] == round((4 / 5) ** 2 + (1 / 5) ** 2, 4)
    assert summary["largest_subtrees"][0] == {"node_id": "d0", "introduced": 2, "share": 0.5}
    empty = structure([]).concentration
    assert empty["packages"] == 0 and empty["fan_in_hhi"] is None and empty["top_dependents"] == []


def test_single_point_is_a_package_most_direct_dependencies_converge_on():
    built = structure([("root", f"d{i}") for i in range(4)] + [(f"d{i}", "core") for i in range(3)])
    assert concentration.single_point(built.rows["core"]) is True
    assert concentration.single_point(built.rows["d0"]) is False                # the project controls a direct dependency itself
    few = structure([("root", "a"), ("root", "b"), ("a", "core"), ("b", "core")])
    assert concentration.single_point(few.rows["core"]) is False                # two is not a pattern


# --- version logic ------------------------------------------------------------------------

@pytest.mark.parametrize("ecosystem,version,expected", [
    ("npm", "1.2.3", ((1, 2, 3), False)), ("npm", "v2.0.0-rc.1", ((2, 0, 0), True)), ("pypi", "2.19.1", ((2, 19, 1), False)),
    ("pypi", "3.0", ((3, 0), False)), ("pypi", "1.0rc1", ((1, 0), True)), ("pypi", "1.0.dev3", ((1, 0), True)),
    ("maven", "2.14.1", ((2, 14, 1), False)), ("cargo", "0.9.0", ((0, 9, 0), False)),
])
def test_release_components_follow_the_ecosystem(ecosystem, version, expected):
    assert release_components(ecosystem, version) == expected


@pytest.mark.parametrize("ecosystem,version", [("pypi", "1!2.0"), ("npm", "not-a-version"), ("vcpkg", "1.0"), ("pypi", "")])
def test_release_components_refuse_what_cannot_be_measured(ecosystem, version):
    with pytest.raises(UnsupportedVersion):
        release_components(ecosystem, version)


def test_version_distance_uses_ecosystem_ordering_not_text():
    releases = {"1.9.0": day("2020-01-01"), "1.10.0": day("2021-01-01"), "2.0.0": day("2023-01-01"), "2.0.1-beta.1": day("2023-06-01")}
    result = version_risk.assess("npm", "1.9.0", meta("2.0.0", releases), AS_OF)
    assert (result["comparison_status"], result["position"], result["comparator"]) == ("COMPARED", "BEHIND", "semver")
    assert (result["major_distance"], result["minor_distance"], result["patch_distance"]) == (1, None, None)
    assert result["releases_behind"] == 2                                       # 1.10.0 and 2.0.0; the beta is not counted
    assert (result["lag_days"], result["installed_age_days"], result["latest_age_days"]) == (1096, 2192, 1096)
    minor = version_risk.assess("npm", "1.9.0", meta("1.10.0", releases), AS_OF)
    assert (minor["major_distance"], minor["minor_distance"], minor["patch_distance"]) == (0, 1, None)     # 1.10 is after 1.9


@pytest.mark.parametrize("installed,latest,position", [("2.0.0", "2.0.0", "UP_TO_DATE"), ("2.0", "2.0.0", "UP_TO_DATE"),
                                                       ("3.0.0rc1", "2.9.0", "AHEAD_OF_LATEST"), ("3.1.0", "3.0.0", "AHEAD_OF_LATEST")])
def test_up_to_date_and_ahead_versions_are_not_behind(installed, latest, position):
    result = version_risk.assess("pypi", installed, meta(latest, {latest: day("2025-01-01")}), AS_OF)
    assert (result["comparison_status"], result["position"], result["major_distance"], result["releases_behind"]) == ("COMPARED", position, 0, 0)
    assert metrics.version_lag_value(result) == 0.0


@pytest.mark.parametrize("ecosystem,installed,latest,reason", [
    ("vcpkg", "1.3.1", "1.4.0", "No version ordering"),
    ("npm", "abc123", "1.0.0", "cannot be ordered safely"),
    ("pypi", "1!1.0", "2.0", "cannot be ordered safely"),
    ("maven", "31.1-jre", "33.0.0-jre", "cannot be ordered safely"),
])
def test_unsafe_comparisons_are_unsupported_never_guessed(ecosystem, installed, latest, reason):
    result = version_risk.assess(ecosystem, installed, meta(latest, {latest: day("2025-01-01"), installed: day("2020-01-01")}), AS_OF)
    assert result["comparison_status"] == "UNSUPPORTED" and reason in result["reason"]
    assert result["major_distance"] is None and result["releases_behind"] is None and result["position"] is None
    assert result["latest_version"] == latest and result["lag_days"] is not None       # what the registry says is still reported
    assert metrics.version_lag_value(result) is None


@pytest.mark.parametrize("installed,metadata,reason", [
    (None, meta("1.0.0", {}), "does not determine an installed version"),
    ("1.0.0", None, "No registry metadata was collected"),
    ("1.0.0", {"status": "NOT_FOUND", "error_code": "NOT_FOUND"}, "NOT_FOUND"),
    ("1.0.0", {"status": "ERROR", "error_code": "TIMEOUT"}, "TIMEOUT"),
    ("1.0.0", meta(None, {"1.0.0": None}), "does not name a latest version"),
])
def test_missing_metadata_is_unknown_with_a_reason(installed, metadata, reason):
    result = version_risk.assess("npm", installed, metadata, AS_OF)
    assert result["comparison_status"] == "UNKNOWN" and reason in result["reason"]
    assert all(result[key] is None for key in ("major_distance", "minor_distance", "releases_behind", "installed_age_days", "position"))


def test_release_dates_are_never_invented():
    compact = version_risk.assess("npm", "1.0.0", meta("2.0.0", {"1.0.0": None, "2.0.0": None}, detail="COMPACT"), AS_OF)
    assert compact["comparison_status"] == "COMPARED" and compact["major_distance"] == 1 and compact["releases_behind"] == 1
    assert all(compact[key] is None for key in ("installed_published_at", "latest_published_at", "installed_age_days", "latest_age_days",
                                                "lag_days", "releases_last_365_days"))
    unlisted = version_risk.assess("npm", "0.9.0", meta("1.0.0", {"1.0.0": day("2025-06-01")}), AS_OF)
    assert unlisted["installed_published_at"] is None and unlisted["installed_age_days"] is None and unlisted["latest_age_days"] == 214


def test_withdrawn_and_unparseable_versions_are_left_out_of_the_count():
    releases = {"1.0.0": day("2024-01-01"), "1.1.0": day("2024-02-01"), "1.2.0": day("2024-03-01"), "weird": day("2024-04-01"), "2.0.0": day("2024-05-01")}
    result = version_risk.assess("npm", "1.0.0", {**meta("2.0.0", releases), "withdrawn_versions": ["1.1.0", "1.0.0"]}, AS_OF)
    assert (result["releases_behind"], result["versions_not_comparable"], result["installed_withdrawn"]) == (2, 1, True)
    truncated = version_risk.assess("npm", "1.0.0", {**meta("2.0.0", releases), "versions_truncated": True}, AS_OF)
    assert truncated["releases_behind"] is None and truncated["major_distance"] == 1


def test_release_frequency_counts_the_year_before_the_analysis():
    releases = {f"1.{i}.0": AS_OF - timedelta(days=30 * i) for i in range(20)}
    result = version_risk.assess("npm", "1.0.0", meta("1.19.0", releases), AS_OF)
    assert result["releases_last_365_days"] == 13


# --- fragility ----------------------------------------------------------------------------

def test_weights_sum_to_one_hundred_and_the_model_is_named():
    assert sum(WEIGHTS.values()) == 100 and sum(prediction.WEIGHTS.values()) == 100
    assert (MODEL_VERSION, risk_propagation.MODEL_VERSION, prediction.MODEL_VERSION) == ("fragility-v1", "graph-risk-v1", "dependency-risk-v1")
    assert [level(s) for s in (0, 33.9, 34, 66.9, 67, 100)] == ["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH"]


def test_a_safe_up_to_date_leaf_dependency_scores_low():
    releases = {"1.0.0": AS_OF - timedelta(days=30)}
    _built, fragility, _risk = analyse([("root", "tidy"), ("root", "other")], metadata={"tidy": meta("1.0.0", releases)})
    result = fragility["tidy"]
    assert result["fragility_score"] == 0.0 and result["fragility_level"] == "LOW" and result["confidence"] == 1.0
    assert result["unknown_factors"] == [] and all(f["status"] == "KNOWN" for f in result["factors"])
    assert (result["dependency_id"], result["package_name"], result["ecosystem"], result["version"], result["model_version"]) == (
        "id-tidy", "tidy", "npm", "1.0.0", "fragility-v1")


def test_score_is_the_sum_of_visible_factor_contributions():
    edges = [("root", f"d{i}") for i in range(12)] + [(f"d{i}", "core") for i in range(12)] + [("core", "x"), ("x", "y")]
    releases = {"1.0.0": day("2019-01-01"), "2.0.0": day("2020-01-01"), "3.0.0": day("2021-01-01"), "4.0.0": day("2022-06-01")}
    _built, fragility, _risk = analyse(edges, metadata={"core": meta("4.0.0", releases)})
    result = fragility["core"]
    assert result["fragility_score"] == round(sum(f["contribution"] for f in result["factors"]), 1)
    by_name = {f["name"]: f for f in result["factors"]}
    assert set(by_name) == set(WEIGHTS) and all(by_name[n]["weight"] == WEIGHTS[n] for n in WEIGHTS)
    assert all(0 <= f["value"] <= 1 and f["contribution"] == round(f["weight"] * f["value"], 2) for f in result["factors"])
    assert by_name["downstream_impact"]["value"] == 1.0 and by_name["version_lag"]["value"] == 1.0 and by_name["release_staleness"]["value"] == 1.0
    assert by_name["graph_centrality"]["value"] == 1.0 and by_name["transitive_depth"]["value"] == 0.25
    assert result["fragility_level"] == "HIGH" and result["fragility_score"] > 80
    assert "12 of 14 other packages depend on it" in by_name["downstream_impact"]["detail"]
    assert "3 major version(s), 3 release(s) behind the latest (4.0.0)" in by_name["version_lag"]["detail"]
    assert by_name["downstream_impact"]["basis"] == "OBSERVED" and by_name["version_lag"]["basis"] == "DERIVED"


def test_scores_are_deterministic():
    edges = [("root", "a"), ("root", "b"), ("a", "c"), ("b", "c"), ("c", "d")]
    options = {"metadata": {"c": meta("2.0.0", {"1.0.0": day("2022-01-01"), "2.0.0": day("2024-01-01")})}, "vulnerabilities": {"c": vuln()}}
    first, second = analyse(edges, **options), analyse(list(reversed(edges)), **options)
    assert first[1] == second[1] and first[2] == second[2]


def test_missing_metadata_lowers_confidence_and_contributes_nothing():
    _built, fragility, _risk = analyse([("root", "a"), ("a", "b")])
    result = fragility["b"]
    assert result["unknown_factors"] == ["version_lag", "release_staleness"] and result["confidence"] == 0.7
    by_name = {f["name"]: f for f in result["factors"]}
    assert by_name["version_lag"] == {**by_name["version_lag"], "value": None, "contribution": 0.0, "status": "UNKNOWN"}
    assert "No registry metadata" in by_name["version_lag"]["detail"]
    assert result["inferred_metrics"]["version"]["comparison_status"] == "UNKNOWN"
    with_metadata = analyse([("root", "a"), ("a", "b")], metadata={"b": meta("1.0.0", {"1.0.0": AS_OF})})[1]["b"]
    assert with_metadata["fragility_score"] == result["fragility_score"]        # unknown was not counted as bad or as good


def test_a_disconnected_package_has_no_depth_factor():
    _built, fragility, _risk = analyse([("root", "a")], extra=["orphan"])
    orphan = fragility["orphan"]
    assert "transitive_depth" in orphan["unknown_factors"] and orphan["observed_metrics"]["connected_to_project"] is False


def test_unsupported_ecosystem_reports_unsupported_comparison():
    _built, fragility, _risk = analyse([("root", "zlib")], versions={"zlib": "1.3.1"}, ecosystem="vcpkg",
                                       metadata={"zlib": meta("1.4.0", {"1.4.0": day("2025-01-01")})})
    version = fragility["zlib"]["inferred_metrics"]["version"]
    assert version["comparison_status"] == "UNSUPPORTED" and version["major_distance"] is None
    assert "version_lag" in fragility["zlib"]["unknown_factors"]


def test_health_profile_reports_collected_facts_and_lists_what_is_unknown():
    releases = {"1.0.0": day("2024-01-01"), "1.1.0": day("2025-07-01")}
    _built, fragility, _risk = analyse([("root", "a"), ("a", "b")], metadata={"a": meta("1.1.0", releases)},
                                       vulnerabilities={"a": vuln(2)}, reachability={"a": reach("REACHABLE")}, analysed=True)
    profile = fragility["a"]["health"]
    assert (profile["installed_version"], profile["latest_release"], profile["release_age_days"], profile["latest_release_age_days"]) == (
        "1.0.0", "1.1.0", 731, 184)
    assert (profile["release_frequency"], profile["known_vulnerability_count"], profile["reachable_vulnerability_count"]) == (1, 2, 1)
    assert (profile["dependency_count"], profile["downstream_dependents"]) == (1, 0)
    assert profile["repository_activity"] is None and profile["metadata_confidence"] == "HIGH"
    assert [u["field"] for u in profile["unknown"]] == ["repository_activity"]
    bare = fragility["b"]["health"]
    assert bare["latest_release"] is None and bare["release_age_days"] is None and bare["metadata_confidence"] == "NONE"
    assert {"latest_release", "release_age_days", "release_frequency", "repository_activity"} <= {u["field"] for u in bare["unknown"]}
    assert all(u["status"] == "UNKNOWN" and u["reason"] for u in bare["unknown"])


def test_metadata_confidence_levels():
    base = {"metadata_status": "COLLECTED", "comparison_status": "COMPARED"}
    assert health.metadata_confidence({**base, "installed_published_at": AS_OF, "latest_published_at": AS_OF}) == ("HIGH", 1.0)
    assert health.metadata_confidence(base) == ("MEDIUM", 0.6)
    assert health.metadata_confidence({**base, "comparison_status": "UNSUPPORTED"}) == ("LOW", 0.3)
    assert health.metadata_confidence({"metadata_status": "ERROR"}) == ("NONE", 0.0)


def test_reachability_count_is_unknown_without_an_analysis():
    _built, fragility, _risk = analyse([("root", "a")], vulnerabilities={"a": vuln()})
    assert fragility["a"]["health"]["reachable_vulnerability_count"] is None
    assert fragility["a"]["inferred_metrics"]["concentration"]["importing_modules"] is None


# --- risk propagation ---------------------------------------------------------------------

def test_exposure_classification_follows_the_direction_of_dependence():
    _built, _fragility, risk = analyse(CHAIN, vulnerabilities={"c": vuln()})
    found = {name: entry["classification"] for name, entry in risk["nodes"].items()}
    assert found == {"c": "DIRECT_VULNERABILITY", "b": "DEPENDENCY_PROPAGATION", "a": "INDIRECT_EXPOSURE", "d": "NO_OBSERVED_PROPAGATION"}
    assert risk["by_classification"] == {"DIRECT_VULNERABILITY": 1, "DEPENDENCY_PROPAGATION": 1, "INDIRECT_EXPOSURE": 1, "NO_OBSERVED_PROPAGATION": 1}
    assert risk["nodes"]["b"]["vulnerability_count"] == 0 and risk["nodes"]["a"]["own_risk"] == 0.0      # exposed, not vulnerable
    assert risk["project"] == {"classification": "INDIRECT_EXPOSURE", "vulnerable_packages": 1, "reachable_from_project": 1,
                               "highest_graph_risk": risk["nodes"]["c"]["own_risk"]}
    assert risk["paths"] == [{"node_id": "c", "path": ["root", "a", "b", "c"], "length": 3, "own_risk": risk["nodes"]["c"]["own_risk"],
                              "path_truncated": False}]


def test_risk_components_are_visible_and_multiply_to_the_node_risk():
    _built, _fragility, risk = analyse(CHAIN, vulnerabilities={"c": vuln(severity="HIGH")}, reachability={"c": reach("REACHABLE")}, analysed=True)
    entry = risk["nodes"]["c"]
    parts = entry["components"]
    assert set(parts) == {"vulnerability_signal", "reachability_signal", "centrality_signal", "downstream_impact", "confidence"}
    assert (parts["vulnerability_signal"], parts["reachability_signal"], parts["confidence"]) == (80, 1.0, 1.0)
    assert entry["own_risk"] == round(80 * 1.0 * parts["centrality_signal"] * parts["downstream_impact"] * 1.0, 1)
    assert 0.6 <= parts["centrality_signal"] <= 1.0 and 0.6 <= parts["downstream_impact"] <= 1.0
    assert entry["model_version"] == "graph-risk-v1" and risk["parameters"]["decay"] == 0.5


def test_influence_halves_with_every_step_away_from_the_vulnerable_package():
    _built, _fragility, risk = analyse(CHAIN, vulnerabilities={"c": vuln()})
    source = risk["nodes"]["c"]["own_risk"]
    assert risk["nodes"]["b"]["propagated_risk"] == round(source * 0.5, 1) and risk["nodes"]["a"]["propagated_risk"] == round(source * 0.25, 1)
    assert risk["nodes"]["b"]["exposure_sources"] == [{"node_id": "c", "distance": 1, "source_risk": source, "influence": round(source * 0.5, 1)}]
    assert risk["nodes"]["c"]["exposes"] == 2 and risk["nodes"]["d"]["propagated_risk"] == 0.0
    assert risk["nodes"]["b"]["graph_risk"] == risk["nodes"]["b"]["propagated_risk"]


@pytest.mark.parametrize("status,signal", [("REACHABLE", 1.0), ("UNKNOWN", 0.7), ("UNSUPPORTED", 0.7), ("NOT_CONFIRMED_REACHABLE", 0.4)])
def test_reachability_strengthens_or_weakens_the_signal_but_never_removes_it(status, signal):
    _built, _fragility, risk = analyse(CHAIN, vulnerabilities={"c": vuln()}, reachability={"c": reach(status)}, analysed=True)
    entry = risk["nodes"]["c"]
    assert entry["components"]["reachability_signal"] == signal and entry["reachability_state"] == status and entry["own_risk"] > 0
    assert entry["classification"] == "DIRECT_VULNERABILITY"                   # a vulnerable dependency stays a vulnerable dependency


def test_vulnerable_is_not_reachable_and_reachable_ranks_higher():
    def risk_for(status):
        return analyse(CHAIN, vulnerabilities={"c": vuln()}, reachability={"c": reach(status)} if status else {}, analysed=bool(status))[2]["nodes"]["c"]
    reachable, not_confirmed, not_analysed = risk_for("REACHABLE"), risk_for("NOT_CONFIRMED_REACHABLE"), risk_for(None)
    assert reachable["own_risk"] > not_analysed["own_risk"] > not_confirmed["own_risk"] > 0
    assert not_analysed["reachability_state"] == "NOT_ANALYSED" and not_analysed["components"]["reachability_signal"] == 0.7
    assert not_analysed["components"]["confidence"] == 0.85 and reachable["components"]["confidence"] == 1.0


def test_unknown_severity_uses_the_midpoint_and_lowers_confidence():
    _built, _fragility, risk = analyse(CHAIN, vulnerabilities={"c": vuln(severity="UNKNOWN")}, reachability={"c": reach("REACHABLE")}, analysed=True)
    assert risk["nodes"]["c"]["components"]["vulnerability_signal"] == 50 and risk["nodes"]["c"]["components"]["confidence"] == 0.9


def test_propagation_through_a_cycle_terminates_and_keeps_the_strongest_source():
    edges = [("root", "a"), ("a", "b"), ("b", "c"), ("c", "a"), ("c", "weak"), ("b", "strong")]
    _built, _fragility, risk = analyse(edges, vulnerabilities={"weak": vuln(severity="LOW"), "strong": vuln(severity="CRITICAL")})
    b = risk["nodes"]["b"]
    assert b["classification"] == "DEPENDENCY_PROPAGATION" and b["exposure_source_count"] == 2
    assert b["exposure_sources"][0]["node_id"] == "strong" and b["propagated_risk"] == b["exposure_sources"][0]["influence"]
    assert risk["nodes"]["c"]["classification"] == "DEPENDENCY_PROPAGATION" and risk["nodes"]["a"]["classification"] == "INDIRECT_EXPOSURE"


def test_no_vulnerabilities_means_no_observed_propagation_not_a_risk_of_zero_everywhere_else():
    _built, _fragility, risk = analyse(DIAMOND)
    assert set(e["classification"] for e in risk["nodes"].values()) == {"NO_OBSERVED_PROPAGATION"}
    assert risk["project"]["classification"] == "NO_OBSERVED_PROPAGATION" and risk["paths"] == []
    assert all(e["components"]["confidence"] is None and e["components"]["reachability_signal"] is None for e in risk["nodes"].values())


def test_a_vulnerable_package_without_a_path_from_the_project_has_no_invented_path():
    _built, _fragility, risk = analyse([("root", "a"), ("x", "y")], vulnerabilities={"y": vuln()})
    assert risk["paths"] == [{"node_id": "y", "path": None, "length": None, "own_risk": risk["nodes"]["y"]["own_risk"],
                              "path_truncated": False}]
    assert risk["project"]["reachable_from_project"] == 0 and risk["nodes"]["x"]["classification"] == "DEPENDENCY_PROPAGATION"
    assert risk["nodes"]["a"]["classification"] == "NO_OBSERVED_PROPAGATION"


# --- indicators ---------------------------------------------------------------------------

def types(found):
    return [item["type"] for item in found]


def test_every_indicator_has_type_severity_confidence_and_evidence():
    edges = [("root", f"d{i}") for i in range(12)] + [(f"d{i}", "core") for i in range(12)]
    releases = {"1.0.0": day("2019-01-01"), "3.0.0": day("2024-01-01")}
    _f, _r, found, _p = predict(edges, "core", metadata={"core": meta("3.0.0", releases)}, vulnerabilities={"core": vuln(5, "CRITICAL")},
                                reachability={"core": reach("REACHABLE")}, analysed=True)
    assert set(types(found)) == {"REACHABLE_VULNERABLE_DEPENDENCY", "VULNERABILITY_CLUSTER", "SINGLE_POINT_DEPENDENCY", "HIGH_DOWNSTREAM_IMPACT",
                                 "HIGH_DEPENDENCY_CONCENTRATION", "HIGH_GRAPH_CENTRALITY", "OUTDATED_DEPENDENCY"}
    for item in found:
        assert set(item) == {"type", "severity", "confidence", "evidence", "basis", "indicator_version"}
        assert item["severity"] in ("LOW", "MEDIUM", "HIGH") and 0 < item["confidence"] <= 1 and item["evidence"] and all(item["evidence"])
        assert item["type"] in prediction.INDICATOR_TYPES


def test_a_plain_dependency_has_no_indicators():
    _f, _r, found, _p = predict([("root", "tidy"), ("root", "other")], "tidy", metadata={"tidy": meta("1.0.0", {"1.0.0": AS_OF - timedelta(days=5)})})
    assert found == []


def test_high_downstream_impact_and_concentration_quote_the_measured_numbers():
    edges = [("root", f"d{i}") for i in range(26)] + [(f"d{i}", "core") for i in range(26)]
    _f, _r, found, _p = predict(edges, "core", metadata={"core": meta("1.0.0", {"1.0.0": AS_OF})})
    by_type = {item["type"]: item for item in found}
    assert by_type["HIGH_DOWNSTREAM_IMPACT"]["severity"] == "HIGH" and "26 packages depend on core" in by_type["HIGH_DOWNSTREAM_IMPACT"]["evidence"][0]
    assert by_type["HIGH_DEPENDENCY_CONCENTRATION"]["severity"] == "HIGH" and "100% of the project's 27 packages" in by_type["HIGH_DEPENDENCY_CONCENTRATION"]["evidence"][0]
    assert by_type["SINGLE_POINT_DEPENDENCY"]["severity"] == "HIGH" and "26 of the project's direct dependencies (100%)" in by_type["SINGLE_POINT_DEPENDENCY"]["evidence"][0]


def test_high_centrality_needs_a_graph_large_enough_to_mean_something():
    small = predict(CHAIN, "b", metadata={"b": meta("1.0.0", {"1.0.0": AS_OF})})[2]
    assert "HIGH_GRAPH_CENTRALITY" not in types(small)
    edges = [("root", f"d{i}") for i in range(6)] + [(f"d{i}", "hub") for i in range(6)] + [("hub", f"leaf{i}") for i in range(6)]
    found = predict(edges, "hub", metadata={"hub": meta("1.0.0", {"1.0.0": AS_OF})})[2]
    central = next(item for item in found if item["type"] == "HIGH_GRAPH_CENTRALITY")
    assert central["severity"] == "HIGH" and "Betweenness centrality" in central["evidence"][0] and central["basis"] == "DERIVED"


def test_high_transitive_depth():
    edges = [("root", "n0")] + [(f"n{i}", f"n{i + 1}") for i in range(8)]
    assert "HIGH_TRANSITIVE_DEPTH" not in types(predict(edges, "n3", metadata={"n3": meta("1.0.0", {"1.0.0": AS_OF})})[2])
    deep = next(i for i in predict(edges, "n4")[2] if i["type"] == "HIGH_TRANSITIVE_DEPTH")
    assert deep["severity"] == "MEDIUM" and "depth 5" in deep["evidence"][0]
    assert next(i for i in predict(edges, "n8")[2] if i["type"] == "HIGH_TRANSITIVE_DEPTH")["severity"] == "HIGH"


@pytest.mark.parametrize("latest,latest_day,severity", [("2.0.0", "2023-06-01", "MEDIUM"), ("3.0.0", "2023-06-01", "HIGH"), ("1.5.0", "2025-06-01", "HIGH"),
                                                        ("1.5.0", "2024-03-01", "MEDIUM"), ("1.5.0", "2023-06-01", None)])
def test_outdated_dependency_needs_a_major_gap_or_a_year_of_lag(latest, latest_day, severity):
    releases = {"1.0.0": day("2023-01-01"), latest: day(latest_day)}
    found = predict([("root", "old")], "old", metadata={"old": meta(latest, releases)})[2]
    outdated = [item for item in found if item["type"] == "OUTDATED_DEPENDENCY"]
    assert ([item["severity"] for item in outdated] or [None]) == [severity]
    if outdated:
        assert f"the registry's latest is {latest}" in outdated[0]["evidence"][0]


def test_outdated_without_release_dates_rests_on_the_version_gap_only():
    found = predict([("root", "old")], "old", metadata={"old": meta("3.0.0", {"1.0.0": None, "3.0.0": None}, detail="COMPACT")})[2]
    outdated = next(item for item in found if item["type"] == "OUTDATED_DEPENDENCY")
    assert outdated["confidence"] == 0.75 and not any("day(s)" in line for line in outdated["evidence"])


def test_rapid_version_gap_needs_many_releases_in_a_short_time():
    fast = {"1.0.0": AS_OF - timedelta(days=120), **{f"1.{i}.0": AS_OF - timedelta(days=120 - 10 * i) for i in range(1, 11)}}
    found = predict([("root", "fast")], "fast", metadata={"fast": meta("1.10.0", fast)})[2]
    rapid = next(item for item in found if item["type"] == "RAPID_VERSION_GAP")
    assert "10 release(s) were published in the 120 day(s)" in rapid["evidence"][0] and rapid["severity"] == "MEDIUM"
    slow = {"1.0.0": AS_OF - timedelta(days=2000), **{f"1.{i}.0": AS_OF - timedelta(days=2000 - 150 * i) for i in range(1, 11)}}
    assert "RAPID_VERSION_GAP" not in types(predict([("root", "slow")], "slow", metadata={"slow": meta("1.10.0", slow)})[2])


def test_vulnerability_cluster_needs_three_distinct_vulnerabilities():
    assert "VULNERABILITY_CLUSTER" not in types(predict([("root", "a")], "a", vulnerabilities={"a": vuln(2)})[2])
    cluster = next(i for i in predict([("root", "a")], "a", vulnerabilities={"a": vuln(3, advisories=("A-1", "A-2", "A-3"))})[2]
                   if i["type"] == "VULNERABILITY_CLUSTER")
    assert cluster["severity"] == "MEDIUM" and "3 distinct known vulnerabilities" in cluster["evidence"][0] and "A-1, A-2, A-3" in cluster["evidence"][1]


def test_reachable_indicator_only_when_phase_four_found_a_path():
    for status in ("NOT_CONFIRMED_REACHABLE", "UNKNOWN", "UNSUPPORTED"):
        found = predict([("root", "a")], "a", vulnerabilities={"a": vuln()}, reachability={"a": reach(status)}, analysed=True)[2]
        assert "REACHABLE_VULNERABLE_DEPENDENCY" not in types(found), status
    assert "REACHABLE_VULNERABLE_DEPENDENCY" not in types(predict([("root", "a")], "a", vulnerabilities={"a": vuln()})[2])
    found = predict([("root", "a")], "a", vulnerabilities={"a": vuln()}, reachability={"a": reach("REACHABLE")}, analysed=True)[2]
    reachable = next(i for i in found if i["type"] == "REACHABLE_VULNERABLE_DEPENDENCY")
    assert reachable["severity"] == "HIGH" and reachable["confidence"] == 0.9 and "app/client.py:5" in reachable["evidence"][1]
    assert "not of exploitability" in reachable["evidence"][2]


def test_insufficient_metadata_says_why_and_estimates_nothing():
    found = predict([("root", "a")], "a")[2]
    assert types(found) == ["INSUFFICIENT_METADATA"]
    assert found[0]["severity"] == "LOW" and "No registry metadata" in found[0]["evidence"][0] and "not estimated" in found[0]["evidence"][1]


def test_no_indicator_is_created_without_evidence():
    assert prediction._indicator("X", "LOW", 1.0, [], "OBSERVED") is None and prediction._indicator("X", "LOW", 1.0, ["", ""], "OBSERVED") is None


# --- predictive dependency risk -----------------------------------------------------------

def test_predictive_risk_lists_every_factor_and_sums_their_contributions():
    edges = [("root", f"d{i}") for i in range(12)] + [(f"d{i}", "core") for i in range(12)]
    releases = {"1.0.0": day("2019-01-01"), "4.0.0": day("2022-01-01")}
    _f, _r, _found, predicted = predict(edges, "core", metadata={"core": meta("4.0.0", releases)}, vulnerabilities={"core": vuln(1, "CRITICAL")},
                                        reachability={"core": reach("REACHABLE")}, analysed=True)
    assert [f["name"] for f in predicted["factors"]] == list(prediction.WEIGHTS)
    assert predicted["score"] == round(sum(f["contribution"] for f in predicted["factors"]), 1)
    assert all(f["contribution"] == round(f["weight"] * f["value"], 1) for f in predicted["factors"])
    assert (predicted["model_version"], predicted["classification"], predicted["level"], predicted["confidence"]) == ("dependency-risk-v1", "PREDICTED", "HIGH", 1.0)
    assert predicted["score"] > 90 and 0 <= predicted["score"] <= 100
    assert "Not a probability" in predicted["meaning"] and "not a prediction of a specific vulnerability" in predicted["meaning"]


def test_the_ten_reference_cases_order_as_expected():
    hub = [("root", f"d{i}") for i in range(12)] + [(f"d{i}", "hub") for i in range(12)]
    fresh = {"1.0.0": AS_OF - timedelta(days=10)}
    safe = predict([("root", "x"), ("root", "y")], "x", metadata={"x": meta("1.0.0", fresh)})[3]
    vulnerable = predict([("root", "x"), ("root", "y")], "x", metadata={"x": meta("1.0.0", fresh)}, vulnerabilities={"x": vuln()})[3]
    not_confirmed = predict([("root", "x"), ("root", "y")], "x", metadata={"x": meta("1.0.0", fresh)}, vulnerabilities={"x": vuln()},
                            reachability={"x": reach("NOT_CONFIRMED_REACHABLE")}, analysed=True)[3]
    reachable = predict([("root", "x"), ("root", "y")], "x", metadata={"x": meta("1.0.0", fresh)}, vulnerabilities={"x": vuln()},
                        reachability={"x": reach("REACHABLE")}, analysed=True)[3]
    central = predict(hub, "hub", metadata={"hub": meta("1.0.0", fresh)})[3]
    outdated = predict([("root", "x"), ("root", "y")], "x", metadata={"x": meta("4.0.0", {"1.0.0": day("2019-01-01"), "4.0.0": day("2025-01-01")})})[3]
    missing = predict([("root", "x"), ("root", "y")], "x")[3]
    unsupported = predict([("root", "x"), ("root", "y")], "x", ecosystem="vcpkg", metadata={"x": meta("2.0.0", {"2.0.0": AS_OF})})[3]
    cyclic = predict([("root", "a"), ("a", "b"), ("b", "a")], "b", metadata={"b": meta("1.0.0", fresh)}, vulnerabilities={"a": vuln()})[3]

    assert safe["score"] == 0.0 and safe["level"] == "LOW" and safe["confidence"] == 1.0
    assert reachable["score"] > vulnerable["score"] > safe["score"] and reachable["score"] > not_confirmed["score"] > safe["score"]
    assert reachable["score"] > vulnerable["score"] > not_confirmed["score"]     # undecided is never ranked below "no path found"
    assert vulnerable["confidence"] == 0.95                                     # reachability not established: an assumed factor counts half
    assert not_confirmed["confidence"] == 1.0 and reachable["confidence"] == 1.0
    assert central["score"] > safe["score"] and outdated["score"] > safe["score"]
    assert missing["score"] == safe["score"] and missing["confidence"] < safe["confidence"]            # unknown is not scored as risk
    assert unsupported["confidence"] < 1.0 and next(f for f in unsupported["factors"] if f["name"] == "version_indicators")["status"] == "UNKNOWN"
    exposure = next(f for f in cyclic["factors"] if f["name"] == "vulnerability_exposure")
    assert exposure["basis"] == "DERIVED" and exposure["value"] > 0 and "No advisory matches this package" in exposure["detail"]


def test_not_confirmed_reachable_is_never_scored_as_safe():
    _f, _r, _found, predicted = predict([("root", "a")], "a", vulnerabilities={"a": vuln()}, reachability={"a": reach("NOT_CONFIRMED_REACHABLE")}, analysed=True)
    reachability = next(f for f in predicted["factors"] if f["name"] == "reachability")
    assert reachability["value"] == 0.2 and reachability["contribution"] > 0 and "not a statement of safety" in reachability["detail"]


def test_evidence_is_grouped_as_observed_derived_predicted_and_recommended():
    edges = [("root", f"d{i}") for i in range(12)] + [(f"d{i}", "requests") for i in range(12)]
    options = {"versions": {"requests": "2.19.1"}, "ecosystem": "pypi",
               "metadata": {"requests": meta("3.0.0", {"2.19.1": day("2018-06-14"), "3.0.0": day("2025-01-01")})},
               "vulnerabilities": {"requests": vuln(2, advisories=("GHSA-x84v-xcm2-53pg", "PYSEC-2018-28"), fixed=("2.20.0",))},
               "reachability": {"requests": reach("REACHABLE", importing_modules=3, use_sites=7)}, "analysed": True}
    built, fragility, risk = analyse(edges, **options)
    row, node = fragility["requests"], risk["nodes"]["requests"]
    found = prediction.indicators(row, node, options["vulnerabilities"]["requests"], options["reachability"]["requests"], built.model.size, True)
    predicted = prediction.predictive_risk(row, node, built.model.size)
    evidence = prediction.evidence(row, node, predicted, found, options["vulnerabilities"]["requests"], options["reachability"]["requests"])
    assert list(evidence) == ["OBSERVED", "DERIVED", "PREDICTED", "RECOMMENDED"]
    observed = " ".join(evidence["OBSERVED"])
    for text in ("Installed version: 2.19.1.", "12 direct and 12 total dependent package(s).", "2 known vulnerability match(es) (GHSA-x84v-xcm2-53pg, PYSEC-2018-28).",
                 "1 reachable, 0 not confirmed", "Imported by 3 application module(s); 7 use site(s).", "Registry's latest version: 3.0.0."):
        assert text in observed, text
    assert any("Exposure classification: DIRECT_VULNERABILITY." == line for line in evidence["DERIVED"])
    assert any(line.startswith("HIGH_DOWNSTREAM_IMPACT") for line in evidence["DERIVED"])
    assert f"Predictive dependency risk {predicted['score']} of 100" in evidence["PREDICTED"][0]
    recommended = " ".join(evidence["RECOMMENDED"])
    assert "Assess upgrading requests to 2.20.0 or later" in recommended and "statically reached" in recommended and "monitoring list" in recommended


def test_low_risk_is_not_described_as_safe_and_no_claims_of_certainty_are_made():
    built, fragility, risk = analyse([("root", "a"), ("root", "b")], metadata={"a": meta("1.0.0", {"1.0.0": AS_OF})})
    predicted = prediction.predictive_risk(fragility["a"], risk["nodes"]["a"], built.model.size)
    evidence = prediction.evidence(fragility["a"], risk["nodes"]["a"], predicted, [], {}, {})
    text = " ".join(line for lines in evidence.values() for line in lines).lower()
    assert "not a statement that the dependency is safe" in text and evidence["RECOMMENDED"] == []
    for claim in ("will be", "guarantee", "certain", "zero-day", "malicious", "exploitable"):
        assert claim not in text, claim


@pytest.mark.parametrize("vulnerabilities,reach,analysed,expected", [
    (2, {"findings": 2, "reachable": 1, "unknown": 1}, False, None),             # no analysis at all
    (0, {}, True, 0),                                                            # nothing to reach
    (0, None, True, 0),
    (2, {"findings": 2, "reachable": 1, "unknown": 1}, True, 1),
    (2, {"findings": 2, "reachable": 0, "not_confirmed": 2, "unknown": 0, "unsupported": 0}, True, 0),   # every finding decided
    (2, {"findings": 2, "reachable": 0, "not_confirmed": 1, "unknown": 1}, True, None),                  # one undecided
    (1, {"findings": 1, "reachable": 0, "unsupported": 1}, True, None),
    (1, {}, True, None),                                                         # the analysis predates the match
    (1, {"findings": 0, "importing_modules": 2}, True, None),
])
def test_reachable_count_never_turns_undecided_into_zero(vulnerabilities, reach, analysed, expected):
    from app.analyzers.fragility.metrics import reachable_count

    value, reason = reachable_count(vulnerabilities, reach, analysed)
    assert value == expected and (reason is None) == (expected is not None)


# --- regression tests from the independent review ----------------------------------------------

def brute_propagation(edges, own):
    """Reference: for every package, each vulnerable package it depends on with the shortest distance (plain BFS per source)."""
    children = {}
    for a, b in edges:
        children.setdefault(a, set()).add(b)
    result = {}
    names = {n for e in edges for n in e if n != "root"}
    for start in names:
        distance, frontier = {start: 0}, [start]
        while frontier:
            following = []
            for node in frontier:
                for child in children.get(node, ()):
                    if child not in distance:
                        distance[child] = distance[node] + 1
                        following.append(child)
            frontier = following
        result[start] = {name: steps for name, steps in distance.items() if name in own and name != start}
    return result


def test_propagation_matches_a_brute_force_reference_on_random_graphs_with_cycles():
    rng = random.Random(7)
    for _ in range(120):
        names = [f"n{i}" for i in range(rng.randint(2, 14))]
        edges = {("root", rng.choice(names))} | {(rng.choice(names), rng.choice(names)) for _ in range(rng.randint(1, 30))}
        edges = [edge for edge in sorted(edges) if edge[0] != edge[1]]
        vulnerable = {name: vuln(severity=rng.choice(["CRITICAL", "HIGH", "LOW", "UNKNOWN"])) for name in names if rng.random() < 0.4}
        built = structure(edges, names)
        risk = risk_propagation.propagate(built, vulnerable, {}, False)["nodes"]
        own = {name: risk[name]["own_risk"] for name in vulnerable}
        reference = brute_propagation(edges, own)
        for name in names:
            sources = reference.get(name, {})
            entry = risk[name]
            expected = max((own[source] * 0.5 ** steps for source, steps in sources.items()), default=0.0)
            assert entry["propagated_risk"] == pytest.approx(expected, abs=0.051), (edges, name)
            assert entry["exposure_source_count"] == len(sources)
            assert len(entry["exposure_sources"]) == min(5, len(sources))
            for listed in entry["exposure_sources"]:
                assert listed["node_id"] != name and sources[listed["node_id"]] == listed["distance"]
            influences = [item["influence"] for item in entry["exposure_sources"]]
            assert influences == sorted(influences, reverse=True)
            if name in vulnerable:
                assert entry["classification"] == "DIRECT_VULNERABILITY"
            elif not sources:
                assert entry["classification"] == "NO_OBSERVED_PROPAGATION"
            else:
                assert entry["classification"] == ("DEPENDENCY_PROPAGATION" if 1 in sources.values() else "INDIRECT_EXPOSURE")


def test_many_vulnerable_packages_are_all_accounted_for_within_bounds():
    """600 vulnerable leaves under one package: every one is counted, the listing stays short, nothing is called unexposed."""
    edges = [("root", "top"), ("top", "mid")] + [("mid", f"v{i:04d}") for i in range(600)]
    built = structure(edges)
    started = time.perf_counter()
    result = risk_propagation.propagate(built, {f"v{i:04d}": vuln(severity="LOW") for i in range(600)}, {}, False)
    assert time.perf_counter() - started < 5
    top, mid = result["nodes"]["top"], result["nodes"]["mid"]
    assert mid["classification"] == "DEPENDENCY_PROPAGATION" and top["classification"] == "INDIRECT_EXPOSURE"
    assert mid["exposure_source_count"] == 600 and top["exposure_source_count"] == 600
    assert len(mid["exposure_sources"]) == 5 and top["propagated_risk"] > 0
    assert result["by_classification"]["DIRECT_VULNERABILITY"] == 600 and result["by_classification"]["NO_OBSERVED_PROPAGATION"] == 0
    assert result["nodes"]["v0599"]["exposes"] == 2
    assert len(result["paths"]) == 50 and result["paths_truncated"] is True and result["project"]["vulnerable_packages"] == 600
    assert result["project"]["reachable_from_project"] == 600


def test_long_paths_are_stored_shortened_and_say_so():
    edges = [("root", "n0000")] + [(f"n{i:04d}", f"n{i + 1:04d}") for i in range(3000)]
    result = risk_propagation.propagate(structure(edges), {"n3000": vuln()}, {}, False)
    (path,) = result["paths"]
    assert path["length"] == 3001 and path["path_truncated"] is True and len(path["path"]) == 14
    assert path["path"][:2] == ["root", "n0000"] and path["path"][-1] == "n3000" and "…" in path["path"]
    import json
    assert len(json.dumps(result["paths"])) < 2000


def test_a_large_cycle_with_many_edges_into_it_is_measured_quickly():
    ring = [(f"c{i:04d}", f"c{(i + 1) % 1500:04d}") for i in range(1500)]
    fans = [(f"f{i:04d}", f"c{(i * 7) % 1500:04d}") for i in range(3000)] + [("root", f"f{i:04d}") for i in range(3000)]
    started = time.perf_counter()
    built = structure(ring + fans)
    assert time.perf_counter() - started < 10
    assert built.rows["c0000"]["in_cycle"] and built.rows["c0000"]["introduced"] == 1499 and built.rows["f0000"]["introduced"] == 1500


def test_unpublished_severity_is_an_assumed_factor_not_a_measured_one():
    _f, risk, _i, predicted = predict([("root", "x"), ("root", "y")], "x", vulnerabilities={"x": vuln(severity="UNKNOWN")},
                                      reachability={"x": reach("REACHABLE")}, analysed=True, metadata={"x": meta("1.0.0", {"1.0.0": AS_OF})})
    exposure = next(f for f in predicted["factors"] if f["name"] == "vulnerability_exposure")
    assert exposure["status"] == "ASSUMED" and exposure["basis"] == "DERIVED" and exposure["value"] == 0.5
    assert "publishes no severity" in exposure["detail"] and "UNKNOWN" not in exposure["detail"]
    assert predicted["confidence"] == 0.85 and risk["severity"] == "UNKNOWN"
    rated = predict([("root", "x"), ("root", "y")], "x", vulnerabilities={"x": vuln(severity="LOW")},
                    reachability={"x": reach("REACHABLE")}, analysed=True, metadata={"x": meta("1.0.0", {"1.0.0": AS_OF})})[3]
    assert next(f for f in rated["factors"] if f["name"] == "vulnerability_exposure")["status"] == "KNOWN" and rated["confidence"] == 1.0


@pytest.mark.parametrize("summary,expected", [
    ({**vuln(distinct=2, fixed=("1.5",)), "with_fix": 1}, "1 of 2 matched advisories list a fixed version (highest: 1.5). Assess that upgrade; it is not known to address the others."),
    ({**vuln(distinct=2, fixed=("1.5", "1.7")), "with_fix": 2}, "Assess upgrading x to 1.7 or later: the highest version the matched advisories list as fixed."),
    ({**vuln(distinct=1, fixed=()), "with_fix": 0}, "No fixed version that can be ordered is published for the matched advisories; review how x is used and whether it can be replaced."),
])
def test_the_upgrade_recommendation_claims_only_what_the_advisories_say(summary, expected):
    fragility, risk, found, predicted = predict([("root", "x")], "x", vulnerabilities={"x": summary})
    assert prediction.evidence(fragility, risk, predicted, found, summary, {})["RECOMMENDED"][0] == expected


def test_recommendations_and_indicator_evidence_state_observations_not_forecasts():
    hub = [("root", f"d{i}") for i in range(12)] + [(f"d{i}", "hub") for i in range(12)]
    fragility, risk, found, predicted = predict(hub, "hub")
    text = " ".join(prediction.evidence(fragility, risk, predicted, found, {}, {})["RECOMMENDED"]
                    + [line for item in found for line in item["evidence"]])
    assert "12 other package(s) depend on it" in text
    for phrase in ("affects", "will ", "grows quickly", "guarantee", "safe"):
        assert phrase not in text, phrase


@pytest.mark.parametrize("ecosystem,installed,latest,releases,expected", [
    # A version component too large to be a release number: nothing is measured, and nothing unstorable is produced.
    ("pypi", "1.0", "99999999999999999999.0", {"1.0": None, "99999999999999999999.0": None}, ("UNSUPPORTED", None, None)),
    ("npm", "1.0.0", "1.99999999999999999999.0", {"1.0.0": None}, ("UNSUPPORTED", None, None)),
    ("pypi", "1.0", "1000000000.0", {"1.0": None, "1000000000.0": None}, ("COMPARED", "BEHIND", 999999999)),
])
def test_absurd_version_numbers_are_not_measured(ecosystem, installed, latest, releases, expected):
    result = version_risk.assess(ecosystem, installed, meta(latest, releases), AS_OF)
    assert (result["comparison_status"], result["position"], result["major_distance"]) == expected
    if expected[0] == "UNSUPPORTED":
        assert "too large" in result["reason"]


def test_impossible_dates_give_unknown_ages_not_zero():
    future = AS_OF + timedelta(days=30)
    result = version_risk.assess("npm", "1.0.0", meta("2.0.0", {"1.0.0": future, "2.0.0": day("2025-06-01")}), AS_OF)
    assert result["installed_age_days"] is None                  # "published" after the analysis: not an age of zero
    assert result["lag_days"] is None                            # the latest predates the installed one: not a lag of zero
    assert result["latest_age_days"] == (AS_OF - day("2025-06-01")).days


def test_dates_without_a_zone_are_read_as_utc():
    naive = datetime(2025, 1, 1)
    result = version_risk.assess("npm", "1.0.0", meta("2.0.0", {"1.0.0": naive, "2.0.0": day("2025-06-01")}), AS_OF)
    assert result["installed_age_days"] == 365 and result["lag_days"] == 151 and result["releases_last_365_days"] == 2


def test_the_installed_version_is_found_under_the_registrys_spelling():
    result = version_risk.assess("pypi", "1.0", meta("2.0.0", {"1.0.0": day("2024-01-01"), "2.0.0": day("2025-01-01")},
                                                     withdrawn_versions=["1.0.0"]), AS_OF)
    assert result["installed_published_at"] == day("2024-01-01") and result["installed_withdrawn"] is True
    absent = version_risk.assess("pypi", "0.9", meta("2.0.0", {"1.0.0": day("2024-01-01"), "2.0.0": day("2025-01-01")}), AS_OF)
    assert absent["installed_published_at"] is None and absent["installed_withdrawn"] is None       # not listed: not known either way


def test_a_deprecated_version_is_not_a_withdrawn_one_and_still_counts_as_a_release():
    releases = {"1.0.0": day("2022-01-01"), "1.1.0": day("2023-01-01"), "2.0.0": day("2025-01-01")}
    result = version_risk.assess("npm", "1.0.0", meta("2.0.0", releases, deprecated_versions=["1.0.0", "1.1.0"]), AS_OF)
    assert result["installed_deprecated"] is True and result["installed_withdrawn"] is False and result["releases_behind"] == 2
    yanked = version_risk.assess("npm", "1.0.0", meta("2.0.0", releases, withdrawn_versions=["1.1.0"]), AS_OF)
    assert yanked["releases_behind"] == 1 and yanked["installed_deprecated"] is False


@pytest.mark.parametrize("installed,latest,releases,detail", [
    ("2.0.0", "3.0.0-rc.1", {"2.0.0": None, "3.0.0-rc.1": None}, "Installed 2.0.0 is 1 major version(s) behind the latest (3.0.0-rc.1)."),
    ("2.0.0-rc.1", "2.0.0", {"2.0.0-rc.1": None, "2.0.0": None}, "Installed 2.0.0-rc.1 is an earlier release of the same version number, 1 release(s) behind the latest (2.0.0)."),
])
def test_version_lag_text_does_not_state_zero_distances(installed, latest, releases, detail):
    factor = metrics.version_lag(version_risk.assess("npm", installed, meta(latest, releases), AS_OF), 20)
    assert factor["detail"] == detail and "0 release(s)" not in factor["detail"] and "0 patch" not in factor["detail"]

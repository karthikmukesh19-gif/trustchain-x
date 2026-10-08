"""Normalisation, direct/transitive classification and graph construction."""

import json

import pytest

from app.analyzers.model import DIRECT, INFERRED, OBSERVED, TRANSITIVE, UNKNOWN
from app.analyzers.normalize import make_purl, node_id, normalize_name
from app.analyzers.parsers import go, java, javascript, python, rust
from app.analyzers.resolve import ROOT, resolve
from app.graph.builder import build_graph, find_paths
from tests.test_dependencies import PACKAGE_LOCK_V3, YARN_V1


def graph_of(*parsed):
    return build_graph(resolve(list(parsed)), "demo")


def nodes_by_id(graph):
    return {node["node_id"]: node for node in graph["nodes"]}


# --- normalisation ----------------------------------------------------------

@pytest.mark.parametrize("ecosystem,raw,expected", [
    ("pypi", "Flask", "flask"), ("pypi", "typing_extensions", "typing-extensions"), ("pypi", "zope.interface", "zope-interface"),
    ("pypi", "Foo__Bar--baz", "foo-bar-baz"), ("npm", "React", "react"), ("npm", "@Scope/Pkg", "@scope/pkg"),
    ("cargo", "serde_json", "serde-json"), ("cargo", "Tokio", "tokio"),
    ("maven", "com.Google.guava:Guava", "com.Google.guava:Guava"), ("golang", "github.com/Azure/azure-sdk", "github.com/Azure/azure-sdk"),
    ("vcpkg", "Boost-Asio", "boost-asio"),
])
def test_normalize_name(ecosystem, raw, expected):
    assert normalize_name(ecosystem, raw) == expected


def test_equivalent_spellings_become_one_package():
    a = python.parse_requirements("a/requirements.txt", "typing_extensions==4.9.0\n")
    b = python.parse_requirements("b/requirements.txt", "Typing.Extensions==4.9.0\n")
    graph = graph_of(a, b)
    assert [n["node_id"] for n in graph["nodes"]] == ["pypi:typing-extensions@4.9.0"]
    assert {e["source_file"] for e in graph["nodes"][0]["evidence"]} == {"a/requirements.txt", "b/requirements.txt"}


@pytest.mark.parametrize("ecosystem,name,version,expected", [
    ("pypi", "requests", "2.31.0", "pkg:pypi/requests@2.31.0"),
    ("pypi", "requests", None, "pkg:pypi/requests"),
    ("npm", "@babel/core", "7.24.0", "pkg:npm/%40babel/core@7.24.0"),
    ("maven", "com.google.guava:guava", "33.0.0-jre", "pkg:maven/com.google.guava/guava@33.0.0-jre"),
    ("golang", "github.com/Gin-Gonic/gin", "v1.9.1", "pkg:golang/github.com/gin-gonic/gin@v1.9.1"),
    ("cargo", "serde", "1.0.195", "pkg:cargo/serde@1.0.195"),
    ("vcpkg", "fmt", "10.2.1", "pkg:generic/fmt@10.2.1?package_manager=vcpkg"),
    ("unknown-ecosystem", "x", "1", None),
])
def test_purl(ecosystem, name, version, expected):
    assert make_purl(ecosystem, name, version) == expected


def test_unresolved_versions_are_explicit():
    graph = graph_of(python.parse_requirements("requirements.txt", "requests>=2.31\n"))
    node = graph["nodes"][0]
    assert node["node_id"] == node_id("pypi", "requests", None) == "pypi:requests@unresolved"
    assert node["version"] is None and node["version_status"] == "UNRESOLVED" and node["version_basis"] == UNKNOWN
    assert node["constraints"] == [">=2.31"] and graph["stats"]["unresolved_versions"] == 1


# --- direct / transitive ----------------------------------------------------

def test_package_lock_gives_observed_direct_and_transitive():
    manifest = javascript.parse_package_json("package.json", json.dumps({"dependencies": {"a": "^1.0.0"}, "devDependencies": {"d": "^1.0.0"}}))
    lock = javascript.parse_package_lock("package-lock.json", PACKAGE_LOCK_V3)
    graph = graph_of(manifest, lock)
    nodes = nodes_by_id(graph)
    assert (nodes["npm:a@1.2.0"]["relationship"], nodes["npm:a@1.2.0"]["relationship_basis"]) == (DIRECT, OBSERVED)
    assert nodes["npm:a@1.2.0"]["version_basis"] == OBSERVED and nodes["npm:a@1.2.0"]["constraints"] == ["^1.0.0"]
    assert (nodes["npm:b@2.5.0"]["relationship"], nodes["npm:b@2.5.0"]["relationship_basis"]) == (TRANSITIVE, OBSERVED)
    assert "Required by a" in nodes["npm:b@2.5.0"]["relationship_reason"]
    assert nodes["npm:c@1.9.0"]["depth"] == 2 and nodes["npm:c@2.0.1"]["depth"] == 3      # two versions, two nodes
    assert nodes["npm:d@1.0.0"]["scopes"] == ["dev"] and nodes["npm:b@2.5.0"]["scopes"] == ["runtime"]
    assert {e["source_file"] for e in nodes["npm:a@1.2.0"]["evidence"]} == {"package.json", "package-lock.json"}
    assert graph["stats"]["unresolved_versions"] == 0 and graph["stats"]["relationship_unknown"] == 0


def test_yarn_lock_with_manifest_and_without():
    lock = javascript.parse_yarn_lock("yarn.lock", YARN_V1)
    manifest = javascript.parse_package_json("package.json", json.dumps({"dependencies": {"@babel/core": "^7.1.0"}}))
    with_manifest = nodes_by_id(graph_of(manifest, lock))
    assert with_manifest["npm:@babel/core@7.24.0"]["relationship"] == DIRECT
    assert (with_manifest["npm:ms@2.1.2"]["relationship"], with_manifest["npm:ms@2.1.2"]["relationship_basis"]) == (TRANSITIVE, OBSERVED)
    assert with_manifest["npm:ms@2.1.2"]["depth"] == 3

    alone = build_graph(resolve([javascript.parse_yarn_lock("yarn.lock", YARN_V1)]), "demo")
    assert all(n["relationship"] == UNKNOWN and n["relationship_basis"] == UNKNOWN for n in alone["nodes"])
    assert all(n["depth"] is None for n in alone["nodes"])                  # no path from the project is established
    assert alone["stats"]["relationship_unknown"] == 3 and alone["stats"]["without_path"] == 3
    assert alone["stats"]["unresolved_edges"] == 1                           # "missing" could not be resolved


def test_lock_without_edges_yields_inferred_transitive_only_with_a_manifest():
    lock_text = json.dumps({"default": {"flask": {"version": "==3.0.0"}, "click": {"version": "==8.1.7"}}, "develop": {}})
    pipfile = python.parse_pipfile("Pipfile", '[packages]\nflask = "*"\n')
    nodes = nodes_by_id(graph_of(pipfile, python.parse_pipfile_lock("Pipfile.lock", lock_text)))
    assert (nodes["pypi:flask@3.0.0"]["relationship"], nodes["pypi:flask@3.0.0"]["relationship_basis"]) == (DIRECT, OBSERVED)
    assert nodes["pypi:flask@3.0.0"]["version"] == "3.0.0"                  # "*" resolved through the lock
    click = nodes["pypi:click@8.1.7"]
    assert (click["relationship"], click["relationship_basis"]) == (TRANSITIVE, INFERRED)
    assert "not declared in Pipfile" in click["relationship_reason"] and click["depth"] is None and click["parents"] == []

    alone = nodes_by_id(graph_of(python.parse_pipfile_lock("Pipfile.lock", lock_text)))
    assert all(n["relationship"] == UNKNOWN for n in alone.values())


def test_gradle_lock_is_not_called_transitive_on_the_strength_of_a_pattern_match():
    build = java.parse_gradle("build.gradle", "dependencies { implementation 'com.google.guava:guava:33.0.0-jre' }")
    lock = java.parse_gradle_lockfile("gradle.lockfile", "com.google.guava:guava:33.0.0-jre=runtimeClasspath\ncom.google.guava:failureaccess:1.0.2=runtimeClasspath\n")
    nodes = nodes_by_id(graph_of(build, lock))
    guava = nodes["maven:com.google.guava:guava@33.0.0-jre"]
    assert (guava["relationship"], guava["relationship_basis"]) == (DIRECT, INFERRED)
    other = nodes["maven:com.google.guava:failureaccess@1.0.2"]
    assert (other["relationship"], other["relationship_basis"]) == (UNKNOWN, UNKNOWN)


def test_go_indirect_is_transitive_with_unknown_parent_and_gets_checksums():
    mod = go.parse_go_mod("go.mod", "module x\n\ngo 1.22\n\nrequire (\n\tgithub.com/a/b v1.0.0\n\tgithub.com/c/d v0.2.0 // indirect\n)\n")
    checksums = go.parse_go_sum("go.sum", "github.com/a/b v1.0.0 h1:AAA=\ngithub.com/zzz/unused v9.9.9 h1:ZZZ=\n")
    graph = graph_of(mod, checksums)
    nodes = nodes_by_id(graph)
    assert set(nodes) == {"golang:github.com/a/b@v1.0.0", "golang:github.com/c/d@v0.2.0"}    # go.sum adds no packages
    assert nodes["golang:github.com/a/b@v1.0.0"]["integrity"] == [{"algorithm": "h1", "value": "AAA="}]
    indirect = nodes["golang:github.com/c/d@v0.2.0"]
    assert (indirect["relationship"], indirect["relationship_basis"]) == (TRANSITIVE, OBSERVED)
    assert indirect["depth"] is None and indirect["parents"] == []            # no fabricated edge
    assert not any(e["target"] == indirect["node_id"] for e in graph["edges"])


def test_cargo_manifest_resolves_through_the_lock():
    manifest = rust.parse_cargo_toml("Cargo.toml", '[package]\nname="demo"\nversion="0.1.0"\n[dependencies]\nserde = "1.0"\nsyn = "2"\n')
    lock = rust.parse_cargo_lock("Cargo.lock", """\
[[package]]
name = "demo"
version = "0.1.0"
dependencies = ["serde", "syn 2.0.48"]
[[package]]
name = "serde"
version = "1.0.195"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["syn 1.0.109"]
[[package]]
name = "syn"
version = "1.0.109"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "syn"
version = "2.0.48"
source = "registry+https://github.com/rust-lang/crates.io-index"
""")
    nodes = nodes_by_id(graph_of(manifest, lock))
    assert "cargo:demo@0.1.0" not in nodes                                    # the project itself is not a dependency
    assert nodes["cargo:syn@2.0.48"]["relationship"] == DIRECT and nodes["cargo:syn@2.0.48"]["constraints"] == ["2"]
    assert nodes["cargo:syn@1.0.109"]["relationship"] == TRANSITIVE and nodes["cargo:syn@1.0.109"]["depth"] == 2
    assert "cargo:syn@unresolved" not in nodes


def test_declared_but_missing_from_lock_stays_unresolved():
    manifest = javascript.parse_package_json("package.json", json.dumps({"dependencies": {"a": "^1.0.0", "ghost": "^9.0.0"}}))
    nodes = nodes_by_id(graph_of(manifest, javascript.parse_package_lock("package-lock.json", PACKAGE_LOCK_V3)))
    ghost = nodes["npm:ghost@unresolved"]
    assert ghost["version"] is None and "not present in package-lock.json" in ghost["version_reason"]
    assert ghost["relationship"] == DIRECT


def test_workspace_member_resolves_against_the_root_lockfile():
    member = javascript.parse_package_json("packages/linked/package.json", json.dumps({"dependencies": {"@scope/e": "^3.0.0"}}))
    nodes = nodes_by_id(graph_of(member, javascript.parse_package_lock("package-lock.json", PACKAGE_LOCK_V3)))
    assert nodes["npm:@scope/e@3.0.0"]["constraints"] == ["^3.0.0"]
    assert "npm:@scope/e@unresolved" not in nodes


def test_manifests_in_unrelated_directories_do_not_borrow_each_others_lock():
    other = javascript.parse_package_json("tools/package.json", json.dumps({"dependencies": {"a": "^1.0.0"}}))
    lock = javascript.parse_package_lock("app/package-lock.json", PACKAGE_LOCK_V3)
    nodes = nodes_by_id(graph_of(other, lock))
    assert "npm:a@unresolved" in nodes and nodes["npm:a@unresolved"]["evidence"][0]["source_file"] == "tools/package.json"


def test_direct_wins_when_evidence_disagrees_and_observed_beats_inferred():
    requirements = python.parse_requirements("requirements.txt", "flask==3.0.0\n")            # DIRECT, INFERRED
    pyproject = python.parse_pyproject("pyproject.toml", '[project]\nname="x"\ndependencies=["flask==3.0.0"]\n')  # DIRECT, OBSERVED
    node = graph_of(requirements, pyproject)["nodes"][0]
    assert (node["relationship"], node["relationship_basis"]) == (DIRECT, OBSERVED)
    assert node["evidence_count"] == 2


# --- graph ------------------------------------------------------------------

def diamond():
    lock = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"a": "1", "b": "1"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"c": "1"}},
        "node_modules/b": {"version": "1.0.0", "dependencies": {"c": "1"}},
        "node_modules/c": {"version": "1.0.0", "dependencies": {"d": "1", "a": "1"}},     # c -> a closes a cycle
        "node_modules/d": {"version": "1.0.0"},
    }})
    return graph_of(javascript.parse_package_lock("package-lock.json", lock))


def test_depth_parents_and_multiple_paths():
    graph = diamond()
    nodes = nodes_by_id(graph)
    assert graph["root"] == {"id": ROOT, "type": "application", "label": "demo"}
    assert [nodes[f"npm:{n}@1.0.0"]["depth"] for n in "abcd"] == [1, 1, 2, 3]
    assert nodes["npm:c@1.0.0"]["parents"] == ["npm:a@1.0.0", "npm:b@1.0.0"]
    assert nodes["npm:c@1.0.0"]["shortest_path_count"] == 2 and nodes["npm:d@1.0.0"]["shortest_path_count"] == 2
    assert nodes["npm:a@1.0.0"]["parents"] == ["npm:c@1.0.0", ROOT] and nodes["npm:a@1.0.0"]["dependents_count"] == 1
    assert graph["stats"]["max_depth"] == 3 and graph["stats"]["by_depth"] == {"1": 2, "2": 1, "3": 1}
    assert graph["stats"]["edges"] == 6 and graph["stats"]["direct"] == 2 and graph["stats"]["transitive"] == 2


def test_every_edge_has_evidence_and_a_basis():
    graph = diamond()
    for edge in graph["edges"]:
        assert edge["type"] == "depends_on" and edge["basis"] in {OBSERVED, INFERRED}
        assert edge["evidence_files"] == ["package-lock.json"]
        assert edge["source"] == ROOT or any(n["node_id"] == edge["source"] for n in graph["nodes"])
        assert any(n["node_id"] == edge["target"] for n in graph["nodes"])


def test_find_paths_terminates_on_cycles_and_returns_all_routes():
    graph = diamond()
    paths = find_paths(graph["edges"], "npm:d@1.0.0")
    assert paths == [[ROOT, "npm:a@1.0.0", "npm:c@1.0.0", "npm:d@1.0.0"], [ROOT, "npm:b@1.0.0", "npm:c@1.0.0", "npm:d@1.0.0"]]
    assert find_paths(graph["edges"], "npm:nonexistent@1") == []


def test_find_paths_is_bounded():
    edges = [{"source": ROOT, "target": "n0"}]
    for layer in range(14):                      # 2^14 distinct paths to the last node
        for a in ("x", "y"):
            edges.append({"source": f"n{layer}", "target": f"{a}{layer}"})
            edges.append({"source": f"{a}{layer}", "target": f"n{layer + 1}"})
    assert len(find_paths(edges, "n5", limit=20, max_length=40)) == 20


def test_empty_input_gives_an_empty_graph():
    graph = build_graph(resolve([]), "demo")
    assert graph["nodes"] == [] and graph["edges"] == []
    assert graph["stats"]["total"] == 0 and graph["stats"]["max_depth"] == 0

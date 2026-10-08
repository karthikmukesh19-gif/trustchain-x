"""Import mapping, the call graph, advisory symbol mapping and the reachability engine (pure functions)."""

import json
import textwrap

import pytest

from app.analyzers.reachability import callgraph, engine, imports, symbols
from app.analyzers.reachability.callgraph import HIGH, LOW, MEDIUM, build_graph
from app.analyzers.reachability.imports import DependencyIndex
from app.analyzers.reachability.symbols import ADVISORY, OPERATOR_SUPPLIED, AffectedSymbol
from app.analyzers.source import ANALYZERS, SourceLimits, base


def dependency(name, version, relationship="DIRECT", display=None, ecosystem="pypi"):
    return {"ecosystem": ecosystem, "node_id": f"{ecosystem}:{name}@{version}", "name": display or name, "normalized_name": name,
            "version": version, "relationship": relationship}


REQUESTS, PYYAML, URLLIB3 = dependency("requests", "2.19.1"), dependency("pyyaml", "5.1", display="PyYAML"), dependency("urllib3", "1.23", "TRANSITIVE")
DEPENDENCIES = [REQUESTS, PYYAML, URLLIB3, dependency("lodash", "4.17.20", ecosystem="npm")]

# The example from the specification: an entry function calls a helper that calls requests.get.
REACHABLE_REPO = {
    "app/main.py": """
        from app.client import fetch

        def handle_request(url):
            return fetch(url)
    """,
    "app/client.py": """
        import requests

        def fetch(url):
            return requests.get(url)
    """,
}


def graph_of(files, dependencies=DEPENDENCIES, tests=(), **options):
    parsed = [ANALYZERS["python"].parse(path, textwrap.dedent(content).encode(), SourceLimits()) for path, content in files.items()]
    return build_graph(parsed, DependencyIndex(dependencies), set(tests), **options)


def edges(graph, kind=None, target=None, source=None):
    return [e for e in graph.edges if (kind is None or e["kind"] == kind) and (target is None or e["target"] == target)
            and (source is None or e["source"] == source)]


def affected(*names, source=ADVISORY, module_only=False):
    return [AffectedSymbol(name, module_only, source, "test") for name in names]


def evaluate(graph, dep, names=(), relationship=None, complete=True, source=ADVISORY, module_only=False, ecosystem="pypi"):
    return engine.evaluate(
        engine.ReachabilityIndex(graph), ecosystem=ecosystem, supported_ecosystems={"pypi"}, dependency_node_id=dep["node_id"],
        relationship=relationship or dep["relationship"], affected=affected(*names, source=source, module_only=module_only),
        source_complete=complete, incomplete_note="1 × SYNTAX_ERROR")


def labels(result, key="path"):
    return [node["label"] for node in result[key]["nodes"]]


# --- import -> dependency mapping ---------------------------------------------------------

def test_import_names_are_mapped_to_dependencies_by_name_or_documented_alias():
    index = DependencyIndex(DEPENDENCIES)
    by_name = index.classify("requests.adapters")
    assert (by_name.resolution, by_name.basis, by_name.dependency["version"], by_name.top_level) == ("DEPENDENCY", imports.NAME_EQUAL, "2.19.1", "requests")
    alias = index.classify("yaml")
    assert (alias.resolution, alias.basis, alias.dependency["node_id"]) == ("DEPENDENCY", imports.KNOWN_IMPORT_NAME, "pypi:pyyaml@5.1")


def test_standard_library_and_unknown_imports_are_never_attached_to_a_dependency():
    index = DependencyIndex(DEPENDENCIES)
    assert index.classify("os.path").resolution == imports.STDLIB and index.classify("json").dependencies == []
    unknown = index.classify("flask.views")
    assert unknown.resolution == imports.UNMAPPED and unknown.dependencies == [] and unknown.note
    assert index.classify("lodash").resolution == imports.UNMAPPED             # an npm package is not a Python import
    assert index.classify("jose").resolution == imports.UNMAPPED               # the alias applies only if python-jose is in the inventory


def test_name_normalisation_follows_the_ecosystem_rules():
    index = DependencyIndex([dependency("typing-extensions", "4.0"), dependency("flask-cors", "3.0")])
    assert index.classify("typing_extensions").dependency["normalized_name"] == "typing-extensions"
    assert index.classify("flask_cors.core").dependency["normalized_name"] == "flask-cors"


def test_an_import_name_two_distributions_could_provide_is_ambiguous():
    index = DependencyIndex([dependency("psycopg2", "2.9"), dependency("psycopg2-binary", "2.9"), dependency("pyjwt", "1.0"), dependency("pyjwt", "2.0")])
    assert index.classify("psycopg2").resolution == imports.AMBIGUOUS and index.classify("psycopg2").dependency is None
    versions = index.classify("jwt")
    assert versions.resolution == "DEPENDENCY" and len(versions.dependencies) == 2 and versions.dependency is None and versions.note


def test_import_records_keep_the_statement_location_and_resolved_version():
    graph = graph_of({**REACHABLE_REPO, "app/extra.py": "import os\nimport flask\nfrom . import missing\nimport yaml as y\n"})
    by_statement = {i["statement"]: i for i in graph.imports}
    observed = by_statement["import requests"]
    assert (observed["source_file"], observed["line"], observed["resolution"], observed["dependency"], observed["resolved_version"],
            observed["dependency_node_ids"], observed["mapping_basis"], observed["scope"]) == (
        "app/client.py", 2, "DEPENDENCY", "requests", "2.19.1", ["pypi:requests@2.19.1"], imports.NAME_EQUAL, "app.client")
    assert by_statement["from app.client import fetch"]["resolution"] == "LOCAL" and by_statement["from app.client import fetch"]["target"] == "app.client"
    assert by_statement["import os"]["resolution"] == imports.STDLIB and by_statement["import flask"]["resolution"] == imports.UNMAPPED
    assert by_statement["from . import missing"]["resolution"] == callgraph.NOT_FOUND
    assert by_statement["import yaml as y"]["dependency"] == "pyyaml"
    assert graph.stats["imports_by_resolution"] == {"DEPENDENCY": 2, "LOCAL": 1, callgraph.NOT_FOUND: 1, "STDLIB": 1, "UNMAPPED": 1}


# --- call graph ---------------------------------------------------------------------------

def test_graph_of_the_reference_example():
    graph = graph_of(REACHABLE_REPO)
    summary = sorted((e["kind"], e["source"], e["target"], e["confidence"]) for e in graph.edges)
    assert summary == [
        ("calls", "app.client:fetch", "ext:requests.get", HIGH),
        ("calls", "app.main:handle_request", "app.client:fetch", HIGH),
        ("imports", "app.client", "ext:requests", HIGH),
        ("imports", "app.main", "app.client", HIGH),
    ]
    call = edges(graph, target="ext:requests.get")[0]
    assert call["evidence"] == {"source_file": "app/client.py", "line": 5, "col": 11, "end_line": 5, "text": "return requests.get(url)"}
    assert "explicitly imported" in call["basis"]
    external = graph.nodes["ext:requests.get"]
    assert (external["kind"], external["qualified"], external["package"], external["dependency_node_ids"]) == (
        "external", "requests.get", "requests", ["pypi:requests@2.19.1"])
    assert graph.stats["modules"] == 2 and graph.stats["functions"] == 2 and graph.stats["unresolved"] == 0
    assert graph_of(REACHABLE_REPO).edges == graph.edges                       # deterministic


def test_every_edge_has_evidence_except_the_structural_constructor_edge():
    graph = graph_of({"app/models.py": """
        import requests

        class Client:
            def __init__(self):
                self.session = requests.Session()

        def make():
            return Client()
    """})
    for edge in graph.edges:
        if edge["kind"] == callgraph.CONSTRUCTS:
            assert (edge["source"], edge["target"]) == ("app.models:Client", "app.models:Client.__init__")
        else:
            assert edge["evidence"]["source_file"] == "app/models.py" and edge["evidence"]["line"] and edge["evidence"]["text"]
    assert edges(graph, source="app.models:make", target="app.models:Client")[0]["confidence"] == HIGH


@pytest.mark.parametrize("statement,call,target", [
    ("import requests as req", "req.get(url)", "ext:requests.get"),
    ("from requests import get", "get(url)", "ext:requests.get"),
    ("from requests import get as fetch_url", "fetch_url(url)", "ext:requests.get"),
    ("import requests.adapters", "requests.adapters.HTTPAdapter()", "ext:requests.adapters.HTTPAdapter"),
    ("from requests.adapters import HTTPAdapter", "HTTPAdapter()", "ext:requests.adapters.HTTPAdapter"),
    ("import yaml", "yaml.load(url)", "ext:yaml.load"),
])
def test_aliased_and_from_imports_resolve_to_the_same_external_name(statement, call, target):
    graph = graph_of({"app/x.py": f"{statement}\n\ndef run(url):\n    return {call}\n"})
    edge, = edges(graph, kind="calls")
    assert (edge["source"], edge["target"], edge["confidence"]) == ("app.x:run", target, HIGH)


def test_local_imports_resolve_across_packages_relative_imports_and_reexports():
    graph = graph_of({
        "backend/app/__init__.py": "",
        "backend/app/api/__init__.py": "from .handlers import handle\n",
        "backend/app/api/handlers.py": """
            from ..services import do_work
            from app.services.worker import Worker

            def handle():
                Worker().run()
                return do_work()
        """,
        "backend/app/services/__init__.py": "from .worker import do_work\n",
        "backend/app/services/worker.py": """
            import requests

            def do_work():
                return requests.get("u")

            class Worker:
                def run(self):
                    return self.step()
                def step(self):
                    return do_work()
        """,
        "backend/main.py": "from app.api import handle\nhandle()\n",
    })
    worker = "backend.app.services.worker"
    reexported = edges(graph, source="backend.app.api.handlers:handle", target=f"{worker}:do_work")[0]
    assert reexported["confidence"] == MEDIUM and reexported["hops"] == ["backend.app.services"] and "re-exported" in reexported["basis"]
    instance = edges(graph, source="backend.app.api.handlers:handle", target=f"{worker}:Worker.run")[0]
    assert instance["confidence"] == MEDIUM and instance["via"] == "instance"
    on_self = edges(graph, source=f"{worker}:Worker.run", target=f"{worker}:Worker.step")[0]
    assert on_self["confidence"] == MEDIUM and on_self["via"] == "self"
    top = edges(graph, source="backend.main", kind="calls")[0]
    assert top["target"] == "backend.app.api.handlers:handle" and top["hops"] == ["backend.app.api"]
    assert graph.stats["unresolved"] == 0


def test_a_local_module_takes_the_name_before_a_dependency_does():
    graph = graph_of({"requests.py": "def get(u):\n    return u\n", "main.py": "import requests\nrequests.get('u')\n"})
    assert [e["target"] for e in edges(graph, kind="calls")] == ["requests:get"]
    assert "ext:requests.get" not in graph.nodes


def test_two_candidate_local_modules_are_not_guessed_between():
    graph = graph_of({"util.py": "def f():\n    pass\n", "pkg/util.py": "def f():\n    pass\n", "pkg/run.py": "import util\nutil.f()\n"})
    assert edges(graph, kind="calls") == []
    assert [u["reason"] for u in graph.unresolved] == [callgraph.AMBIGUOUS_LOCAL_MODULE]


def test_confidence_reflects_how_the_callee_was_bound():
    graph = graph_of({"app/x.py": """
        import requests

        send = requests.post

        def run(url):
            requests.get(url)                       # direct
            send(url)                               # alias
            requests.Session().head(url)            # attribute of a call result
            return map(requests.put, [url])         # reference, not a call
    """})
    by_target = {e["target"]: (e["kind"], e["confidence"]) for e in graph.edges if e["source"] == "app.x:run"}
    assert by_target == {
        "ext:requests.get": ("calls", HIGH), "ext:requests.post": ("calls", MEDIUM), "ext:requests.Session": ("calls", HIGH),
        "ext:requests.Session.head": ("calls", LOW), "ext:requests.put": ("references", LOW)}


def test_unresolved_and_dynamic_calls_are_recorded_not_turned_into_edges():
    graph = graph_of({"app/x.py": """
        import importlib
        import requests

        def run(name, obj):
            obj.send()
            getattr(requests, name)("u")
            importlib.import_module(name)
            eval(name)
    """})
    assert [e["target"] for e in edges(graph, kind="calls")] == []
    reasons = {u["reason"]: u for u in graph.unresolved}
    assert set(reasons) == {base.UNKNOWN_RECEIVER, base.DYNAMIC_GETATTR, base.DYNAMIC_IMPORT, base.DYNAMIC_EVAL, base.CALL_RESULT}
    dynamic = reasons[base.DYNAMIC_GETATTR]
    assert dynamic["subject_package"] == "requests" and dynamic["source"] == "app.x:run"
    assert dynamic["evidence"] == {"source_file": "app/x.py", "line": 7, "col": 4, "text": 'getattr(requests, name)("u")'}
    assert graph.stats["unresolved_by_reason"][base.DYNAMIC_EVAL] == 1


def test_standard_library_and_unmapped_packages_stay_outside_the_graph():
    graph = graph_of({"app/x.py": "import os, json, flask\n\ndef run():\n    os.getcwd(); json.dumps({}); flask.Flask('x'); print('x')\n"})
    assert graph.edges == [] and graph.unresolved == []
    assert not [n for n in graph.nodes.values() if n["kind"] == "external"]


def test_files_that_did_not_parse_are_left_out_of_the_graph():
    graph = graph_of({"ok.py": "import requests\nrequests.get('u')\n", "bad.py": "def (:\n"})
    assert graph.stats["modules"] == 1 and "bad" not in graph.nodes


def test_edge_limit_truncates_and_says_so():
    graph = graph_of({"x.py": "import requests\n" + "".join(f"requests.f{i}()\n" for i in range(20))}, max_edges=5)
    assert len(graph.edges) == 5 and graph.truncated and graph.stats["truncated"] is True


# --- advisory symbol mapping --------------------------------------------------------------

def record(**specific):
    return {"id": "TEST-1", "affected": [
        {"package": {"ecosystem": "PyPI", "name": "Requests"}, "ecosystem_specific": specific},
        {"package": {"ecosystem": "npm", "name": "requests"}, "ecosystem_specific": {"affected_functions": ["requests.npm_only"]}},
        {"package": {"ecosystem": "PyPI", "name": "other"}, "ecosystem_specific": {"affected_functions": ["other.f"]}}]}


def test_affected_functions_published_by_an_advisory_are_used_as_published():
    found = symbols.from_advisory(record(affected_functions=["requests.sessions.Session.send", "requests.get"]), "pypi", "requests")
    assert [(s.symbol, s.source, s.module_only) for s in found] == [("requests.get", ADVISORY, False), ("requests.sessions.Session.send", ADVISORY, False)]
    assert found[0].origin == "affected[].ecosystem_specific.affected_functions"


def test_import_paths_and_symbols_published_by_an_advisory_are_combined():
    found = symbols.from_advisory(record(imports=[{"path": "requests.sessions", "symbols": ["Session.send"]}, {"path": "requests.utils"}]),
                                  "pypi", "requests")
    assert [(s.symbol, s.module_only) for s in found] == [("requests.sessions.Session.send", False), ("requests.utils", True)]


@pytest.mark.parametrize("raw", [
    None, {}, {"affected": "all"}, {"affected": [None, 5, {"package": "x"}]},
    {"id": "X", "summary": "Vulnerability in requests.get() and Session.send", "details": "call `requests.get`", "affected": [
        {"package": {"ecosystem": "PyPI", "name": "requests"}, "ranges": []}]},
    record(affected_functions="requests.get"), record(affected_functions=[5, None, "", "not a symbol!", "a..b", "x" * 300, "1abc"]),
    record(imports=[{"symbols": ["get"]}, "requests", {"path": "bad path"}]),
])
def test_nothing_is_derived_when_the_advisory_publishes_no_usable_symbols(raw):
    assert symbols.from_advisory(raw, "pypi", "requests") == []


def test_symbols_are_capped():
    found = symbols.from_advisory(record(affected_functions=[f"requests.f{i}" for i in range(500)]), "pypi", "requests")
    assert len(found) == symbols.MAX_SYMBOLS


@pytest.mark.parametrize("wanted,observed,expected", [
    ("requests.get", "requests.get", symbols.EXACT),
    ("requests.api.get", "requests.get", symbols.NAME),                        # top-level re-export
    ("requests.sessions.Session.send", "requests.Session.send", symbols.NAME),
    ("requests.sessions.Session", "requests.sessions.Session.send", symbols.EXACT),   # a member of an affected class
    ("requests.sessions.Session.send", "requests.sessions.Session", None),     # the class is used, the method is not observed
    ("requests.sessions.Session.get", "requests.get", None),                   # a function is not a method of the same name
    ("requests.api.get", "requests.post", None),
    ("requests.api.get", "urllib3.get", None),
    ("requests.get", "requests", None),
    ("yaml.load", "yaml.load_all", None),
])
def test_matching_an_observed_name_to_an_affected_symbol(wanted, observed, expected):
    assert symbols.match(AffectedSymbol(wanted, False, ADVISORY, "t"), observed) == expected


def test_a_module_level_mapping_matches_anything_inside_that_module_only():
    module = AffectedSymbol("requests.utils", True, ADVISORY, "t")
    assert symbols.match(module, "requests.utils.get_netrc_auth") == symbols.EXACT and symbols.match(module, "requests.utils") == symbols.EXACT
    assert symbols.match(module, "requests.get") is None and symbols.match(module, "requests.utilsx.f") is None


def mapping(**overrides):
    return {"advisory_id": "GHSA-x84v-xcm2-53pg", "ecosystem": "PyPI", "package": "Requests", "symbols": ["requests.sessions.Session.send"],
            "source_url": "https://github.com/psf/requests/pull/4718", "note": "from the fix commit", **overrides}


def test_operator_mappings_are_loaded_validated_and_labelled(tmp_path):
    file = tmp_path / "map.json"
    file.write_text(json.dumps({"mappings": [mapping(aliases=["CVE-2018-18074"]), mapping(advisory_id="OTHER-1", package="yaml")]}))
    entries, problems = symbols.load_operator_mappings(file)
    assert problems == [] and len(entries) == 2 and entries[0]["package"] == "requests" and entries[0]["ecosystem"] == "pypi"
    for identifiers in (["GHSA-x84v-xcm2-53pg"], ["PYSEC-1", "CVE-2018-18074"]):
        found = symbols.from_operator(entries, identifiers, "pypi", "requests")
        assert [(s.symbol, s.source, s.origin, s.note) for s in found] == [
            ("requests.sessions.Session.send", OPERATOR_SUPPLIED, "https://github.com/psf/requests/pull/4718", "from the fix commit")]
    assert symbols.from_operator(entries, ["GHSA-zzzz"], "pypi", "requests") == []
    assert symbols.from_operator(entries, ["GHSA-x84v-xcm2-53pg"], "pypi", "urllib3") == []


@pytest.mark.parametrize("bad,problem", [
    ({"source_url": "http://example.com/x"}, "https"), ({"source_url": None}, "source_url"), ({"source_url": "https://user:pw@example.com/"}, "https"),
    ({"symbols": []}, "symbols"), ({"symbols": ["rm -rf /"]}, "symbols"), ({"advisory_id": "bad id"}, "advisory_id"),
    ({"ecosystem": "npm"}, "ecosystem"), ({"package": ""}, "package"),
])
def test_invalid_operator_mappings_are_ignored_and_reported(tmp_path, bad, problem):
    file = tmp_path / "map.json"
    file.write_text(json.dumps([mapping(**bad), "junk", mapping()]))
    entries, problems = symbols.load_operator_mappings(file)
    assert len(entries) == 1 and len(problems) == 2 and problem in problems[0] and problems[0].startswith("Mapping 1 was ignored")


def test_missing_unreadable_or_oversized_mapping_files_give_an_empty_mapping(tmp_path):
    assert symbols.load_operator_mappings(None) == ([], []) and symbols.load_operator_mappings(tmp_path / "absent.json") == ([], [])
    broken = tmp_path / "broken.json"
    broken.write_text("{not json")
    assert symbols.load_operator_mappings(broken)[0] == [] and "could not be read" in symbols.load_operator_mappings(broken)[1][0]
    wrong = tmp_path / "wrong.json"
    wrong.write_text('{"mappings": "all"}')
    assert "must contain a list" in symbols.load_operator_mappings(wrong)[1][0]
    huge = tmp_path / "huge.json"
    huge.write_text("[" + " " * (symbols.MAX_MAPPING_BYTES + 10) + "]")
    assert "too large" in symbols.load_operator_mappings(huge)[1][0]


def test_the_shipped_mapping_file_is_empty():
    from app.services.reachability import DEFAULT_MAPPINGS
    assert symbols.load_operator_mappings(DEFAULT_MAPPINGS) == ([], [])


# --- reachability engine ------------------------------------------------------------------

def test_reference_example_is_reachable_with_the_full_path_and_high_confidence():
    result = evaluate(graph_of(REACHABLE_REPO), REQUESTS, ["requests.get"])
    assert (result["status"], result["confidence"], result["reason"]) == (engine.REACHABLE, HIGH, engine.PATH_FOUND)
    assert labels(result) == ["app.main:handle_request", "app.client:fetch", "requests.get"]
    path = result["path"]
    assert [(e["kind"], e["source"], e["target"], e["evidence"]["source_file"], e["evidence"]["line"]) for e in path["edges"]] == [
        ("calls", "app.main:handle_request", "app.client:fetch", "app/main.py", 5),
        ("calls", "app.client:fetch", "ext:requests.get", "app/client.py", 5)]
    assert path["length"] == 2 and path["start_is_entry"] is True and path["through_tests_only"] is False
    assert result["matched_symbol"] == {"symbol": "requests.get", "module_only": False, "source": ADVISORY, "origin": "test", "note": None,
                                        "observed": "requests.get", "match": symbols.EXACT}
    assert "does not show that the vulnerability can be exploited" in result["explanation"]


def test_direct_use_from_module_level_code_is_reachable():
    result = evaluate(graph_of({"script.py": "import requests\nrequests.get('u')\n"}), REQUESTS, ["requests.get"])
    assert result["status"] == engine.REACHABLE and labels(result) == ["script", "requests.get"]


def test_installed_but_affected_functionality_not_observed_is_not_confirmed_never_safe():
    result = evaluate(graph_of(REACHABLE_REPO), REQUESTS, ["requests.sessions.Session.send"])
    assert (result["status"], result["confidence"], result["reason"], result["path"]) == (engine.NOT_CONFIRMED_REACHABLE, MEDIUM, engine.NO_PATH_FOUND, None)
    assert result["usage"]["level"] == engine.USAGE_CALLED and "not a statement that the application is safe" in result["explanation"]
    never_imported = evaluate(graph_of(REACHABLE_REPO), PYYAML, ["yaml.load"])
    assert (never_imported["status"], never_imported["confidence"], never_imported["usage"]["level"]) == (
        engine.NOT_CONFIRMED_REACHABLE, HIGH, engine.USAGE_NOT_OBSERVED)


def test_importing_a_module_is_not_using_a_function_in_it():
    graph = graph_of({"x.py": "import requests.utils\nfrom requests import get\n"})
    result = evaluate(graph, REQUESTS, ["requests.utils", "requests.get"], module_only=False)
    assert result["status"] == engine.NOT_CONFIRMED_REACHABLE and result["usage"]["level"] == engine.USAGE_IMPORTED


def test_without_a_symbol_mapping_the_result_is_unknown_with_usage_evidence():
    result = evaluate(graph_of(REACHABLE_REPO), REQUESTS)
    assert (result["status"], result["confidence"], result["reason"], result["path"]) == (engine.UNKNOWN, None, engine.SYMBOL_MAPPING_UNKNOWN, None)
    assert result["symbol_mapping"] == symbols.SYMBOL_MAPPING_UNKNOWN and result["affected_symbols"] == []
    usage = result["usage"]
    assert usage["imported"] is True and usage["used_names"] == ["requests.get"]
    assert [(s["source_file"], s["line"], s["text"]) for s in usage["import_sites"]] == [("app/client.py", 2, "import requests")]
    assert [(s["symbol"], s["used"], s["kind"], s["line"]) for s in usage["use_sites"]] == [("app.client:fetch", "requests.get", "calls", 5)]
    assert labels(result, "usage_path") == ["app.main:handle_request", "app.client:fetch", "requests.get"]


def test_a_dependency_of_a_dependency_is_unknown_because_its_callers_are_not_analysed():
    result = evaluate(graph_of(REACHABLE_REPO), URLLIB3, ["urllib3.poolmanager.PoolManager"])
    assert (result["status"], result["reason"], result["confidence"]) == (engine.UNKNOWN, engine.DEPENDENCY_SOURCE_NOT_ANALYSED, None)
    direct_use = graph_of({"x.py": "import urllib3\nurllib3.PoolManager()\n"})
    assert evaluate(direct_use, URLLIB3, ["urllib3.PoolManager"])["status"] == engine.REACHABLE       # imported by the application itself


def test_incomplete_source_makes_a_missing_path_unknown_but_never_hides_a_found_one():
    graph = graph_of(REACHABLE_REPO)
    missing = evaluate(graph, REQUESTS, ["requests.sessions.Session.send"], complete=False)
    assert (missing["status"], missing["reason"]) == (engine.UNKNOWN, engine.INCOMPLETE_SOURCE) and "1 × SYNTAX_ERROR" in missing["explanation"]
    assert evaluate(graph, REQUESTS, ["requests.get"], complete=False)["status"] == engine.REACHABLE


@pytest.mark.parametrize("body,reason", [
    ("getattr(requests, name)('u')", base.DYNAMIC_GETATTR),
    ("eval(name)", base.DYNAMIC_EVAL),
    ("importlib.import_module(name)", base.DYNAMIC_IMPORT),
])
def test_dynamic_behaviour_that_could_reach_the_package_gives_unknown(body, reason):
    graph = graph_of({"x.py": f"import importlib\nimport requests\n\ndef run(name):\n    return {body}\n"})
    result = evaluate(graph, REQUESTS, ["requests.sessions.Session.send"])
    assert (result["status"], result["reason"], result["confidence"]) == (engine.UNKNOWN, engine.DYNAMIC_CODE, None)
    assert [(s["reason"], s["source_file"], s["line"]) for s in result["dynamic_sites"]] == [(reason, "x.py", 5)]


def test_a_star_import_of_the_package_gives_unknown():
    result = evaluate(graph_of({"x.py": "from requests import *\n\ndef run():\n    return get('u')\n"}), REQUESTS, ["requests.sessions.Session.send"])
    assert (result["status"], result["reason"]) == (engine.UNKNOWN, engine.DYNAMIC_CODE)
    assert result["dynamic_sites"][0]["reason"] == base.STAR_IMPORT


def test_dynamic_access_to_an_unrelated_object_does_not_make_everything_unknown():
    graph = graph_of({"x.py": "import requests\n\ndef run(obj, name):\n    requests.get('u')\n    return getattr(obj, name)()\n"})
    result = evaluate(graph, REQUESTS, ["requests.sessions.Session.send"])
    assert (result["status"], result["confidence"]) == (engine.NOT_CONFIRMED_REACHABLE, LOW)      # lower confidence, not a different answer


def test_other_ecosystems_are_unsupported():
    result = evaluate(graph_of(REACHABLE_REPO), DEPENDENCIES[3], ["lodash.template"], ecosystem="npm")
    assert (result["status"], result["reason"], result["confidence"], result["usage"]) == (engine.UNSUPPORTED, engine.LANGUAGE_NOT_SUPPORTED, None, None)
    assert engine.evaluate(None, ecosystem="pypi", supported_ecosystems=set(), dependency_node_id="x", relationship="DIRECT",
                           affected=[], source_complete=True)["status"] == engine.UNSUPPORTED


def test_confidence_is_the_weakest_link_of_path_match_and_mapping_source():
    graph = graph_of({"x.py": """
        import requests

        def direct():
            return requests.get("u")

        def indirect():
            return requests.Session().send("r")
    """})
    assert evaluate(graph, REQUESTS, ["requests.get"])["confidence"] == HIGH
    assert evaluate(graph, REQUESTS, ["requests.get"], source=OPERATOR_SUPPLIED)["confidence"] == MEDIUM
    by_instance = evaluate(graph, REQUESTS, ["requests.Session.send"])
    assert (by_instance["status"], by_instance["confidence"]) == (engine.REACHABLE, LOW)          # attribute of a call result
    assert by_instance["path"]["edges"][-1]["via"] == "instance"


def test_an_exact_match_is_preferred_and_the_strongest_path_is_chosen():
    graph = graph_of({"x.py": """
        import requests
        alias = requests.get

        def weak():
            return alias("u")

        def strong():
            return requests.get("u")
    """})
    result = evaluate(graph, REQUESTS, ["requests.get"])
    assert result["confidence"] == HIGH and labels(result) == ["x:strong", "requests.get"]


def test_application_entry_points_are_preferred_over_test_code():
    files = {"app/client.py": "import requests\n\ndef fetch():\n    return requests.get('u')\n",
             "tests/test_client.py": "import requests\n\ndef test_it():\n    requests.get('u')\n"}
    result = evaluate(graph_of(files, tests={"tests/test_client.py"}), REQUESTS, ["requests.get"])
    assert labels(result)[0] == "app.client:fetch" and result["path"]["through_tests_only"] is False
    only_tests = evaluate(graph_of({"tests/test_client.py": files["tests/test_client.py"]}, tests={"tests/test_client.py"}), REQUESTS, ["requests.get"])
    assert only_tests["status"] == engine.REACHABLE and only_tests["path"]["through_tests_only"] is True
    assert "starts in test code" in only_tests["explanation"]


def test_transitive_paths_and_cycles_are_traversed_once():
    graph = graph_of({"x.py": """
        import requests

        def a():
            return b()

        def b():
            return c() or a()

        def c():
            return d()

        def d():
            return requests.get("u")

        def entry():
            return a()
    """})
    result = evaluate(graph, REQUESTS, ["requests.get"])
    assert labels(result) == ["x:entry", "x:a", "x:b", "x:c", "x:d", "requests.get"] and result["path"]["start_is_entry"] is True


def test_a_cycle_nothing_enters_still_reports_the_call_site():
    graph = graph_of({"x.py": "import requests\n\ndef a():\n    requests.get('u')\n    return b()\n\ndef b():\n    return a()\n"})
    result = evaluate(graph, REQUESTS, ["requests.get"])
    assert result["status"] == engine.REACHABLE and labels(result)[-2:] == ["x:a", "requests.get"]


def test_long_paths_are_stored_shortened_from_the_start():
    functions = "".join(f"def f{i}():\n    return f{i + 1}()\n\n" for i in range(100))
    graph = graph_of({"x.py": f"import requests\n\n{functions}def f100():\n    return requests.get('u')\n"})
    path = evaluate(graph, REQUESTS, ["requests.get"])["path"]
    assert path["length"] == engine.MAX_PATH and path["truncated"] is True and path["nodes"][-1]["label"] == "requests.get"


def test_path_search_handles_a_large_graph():
    functions = "".join(f"def f{i}():\n    return f{(i * 7 + 1) % 3000}(), f{(i * 13 + 5) % 3000}()\n\n" for i in range(3000))
    graph = graph_of({"x.py": f"import requests\n\n{functions}def leaf():\n    return requests.get('u')\n\ndef main():\n    return f0(), leaf()\n"})
    result = evaluate(graph, REQUESTS, ["requests.get"])
    assert result["status"] == engine.REACHABLE and labels(result) == ["x:main", "x:leaf", "requests.get"]


def test_usage_lists_are_bounded():
    calls = "".join(f"    requests.get('{i}')\n" for i in range(60))
    usage = evaluate(graph_of({"x.py": f"import requests\n\ndef run():\n{calls}"}), REQUESTS)["usage"]
    assert usage["use_site_count"] == 60 and len(usage["use_sites"]) == engine.MAX_SITES


# --- further graph cases ------------------------------------------------------------------

def test_names_from_a_local_star_import_are_followed_and_external_ones_are_not_guessed():
    graph = graph_of({
        "pkg/__init__.py": "from .impl import *\nfrom requests import *\n",
        "pkg/impl.py": "def work():\n    return 1\n",
        "main.py": "from pkg import work, get\n\ndef run():\n    return work(), get('u')\n",
    })
    call = edges(graph, source="main:run", kind="calls")
    assert [(e["target"], e["confidence"], e["hops"]) for e in call] == [("pkg.impl:work", MEDIUM, ["pkg"])]
    assert [(u["reason"], u["source"]) for u in graph.unresolved] == [(base.STAR_IMPORT, "main:run")]


def test_module_values_and_missing_names_are_unresolved_not_edges():
    graph = graph_of({
        "app/config.py": "import os\nsettings = os.environ\n\ndef load():\n    return 1\n\nclass Box:\n    def open(self):\n        return 1\n",
        "app/main.py": """
            from app import config
            from app.config import settings, Box, load, gone
            import app.config

            def run():
                settings.get("x")            # a module-level value, not a definition
                gone()                       # not defined in the module
                Box.close()                  # not a member of the class
                load().thing()               # attribute of a function's result
                app.config()                 # a module is not callable
                return config.load(), Box().open(), Box.open
        """,
    })
    made = sorted({(e["target"], e["kind"], e["confidence"]) for e in edges(graph, source="app.main:run")})
    assert len(edges(graph, source="app.main:run", target="app.config:load")) == 2            # one edge per call site
    assert made == [("app.config:Box", "calls", HIGH), ("app.config:Box.open", "calls", MEDIUM), ("app.config:Box.open", "references", LOW),
                    ("app.config:load", "calls", HIGH)]
    assert sorted(u["reason"] for u in graph.unresolved) == [
        base.CALL_RESULT, callgraph.LOCAL_SYMBOL_NOT_FOUND, callgraph.LOCAL_SYMBOL_NOT_FOUND, callgraph.LOCAL_SYMBOL_NOT_FOUND,
        callgraph.LOCAL_SYMBOL_NOT_FOUND]


def test_same_file_classes_functions_and_instances():
    graph = graph_of({"x.py": """
        def helper():
            return 1

        class Job:
            def __init__(self):
                self.n = helper()
            def run(self):
                return self.n

        def main():
            job = Job()
            job.run()
            job.missing()
            helper().bit_length()
            return Job.run, helper
    """})
    made = sorted((e["target"], e["kind"], e["confidence"], e.get("via")) for e in edges(graph, source="x:main"))
    assert made == [("x:Job", "calls", HIGH, None), ("x:Job.run", "calls", MEDIUM, "instance"), ("x:Job.run", "references", LOW, None),
                    ("x:helper", "calls", HIGH, None), ("x:helper", "references", LOW, None)]
    assert edges(graph, kind=callgraph.CONSTRUCTS)[0]["target"] == "x:Job.__init__"
    assert sorted(u["reason"] for u in graph.unresolved if u["source"] == "x:main") == [base.CALL_RESULT, base.CALL_RESULT]
    # Constructing the class reaches what its __init__ calls.
    result = engine.ReachabilityIndex(graph).best_path({"x:helper"})
    assert result is not None


def test_a_use_of_an_ambiguously_provided_import_is_unresolved():
    graph = graph_of({"x.py": "import psycopg2\npsycopg2.connect('dsn')\n"},
                     dependencies=[dependency("psycopg2", "2.9"), dependency("psycopg2-binary", "2.9")])
    assert graph.edges == [] and [u["reason"] for u in graph.unresolved] == [imports.AMBIGUOUS]
    assert graph.imports[0]["resolution"] == imports.AMBIGUOUS and len(graph.imports[0]["dependency_node_ids"]) == 2


def test_relative_imports_above_the_repository_root_do_not_resolve():
    graph = graph_of({"a.py": "from ... import x\nfrom .missing import y\nx(); y()\n"})
    assert [i["resolution"] for i in graph.imports] == [callgraph.NOT_FOUND, callgraph.NOT_FOUND]
    assert {u["reason"] for u in graph.unresolved} == {callgraph.NOT_FOUND} and graph.edges == []


def test_reexport_chains_that_loop_end_unresolved():
    graph = graph_of({"a.py": "from b import thing\n", "b.py": "from a import thing\n", "c.py": "from a import thing\nthing()\n"})
    assert edges(graph, kind="calls") == [] and [u["reason"] for u in graph.unresolved] == [callgraph.LOCAL_SYMBOL_NOT_FOUND]


def test_function_level_and_literal_dynamic_imports_are_edges_from_that_function():
    graph = graph_of({"x.py": """
        import importlib

        def lazy():
            import requests
            return requests.get("u")

        def plugin():
            return importlib.import_module("yaml").safe_load("a: 1")
    """})
    imported = {(e["source"], e["target"], e["confidence"]) for e in edges(graph, kind="imports")}
    assert imported == {("x:lazy", "ext:requests", HIGH), ("x:plugin", "ext:yaml", MEDIUM)}
    assert ("x:lazy", "ext:requests.get") in {(e["source"], e["target"]) for e in edges(graph, kind="calls")}
    assert graph.imports[-1]["dynamic"] is True and graph.imports[-1]["dependency"] == "pyyaml"


# --- review findings ------------------------------------------------------------------------

def test_a_use_that_only_shares_a_name_with_the_affected_symbol_is_unknown_not_reachable():
    torch = dependency("torch", "2.0")
    graph = graph_of({"x.py": "import torch\n\ndef run(p):\n    return torch.load(p)\n"}, dependencies=[torch])
    result = evaluate(graph, torch, ["torch.jit.load"])
    assert (result["status"], result["reason"], result["confidence"], result["path"]) == (engine.UNKNOWN, engine.SYMBOL_MATCH_UNCERTAIN, None, None)
    assert result["matched_symbol"]["match"] == symbols.NAME and result["matched_symbol"]["observed"] == "torch.load"
    assert labels(result, "usage_path") == ["x:run", "torch.load"] and "nothing is concluded" in result["explanation"]
    reexport = evaluate(graph_of(REACHABLE_REPO), REQUESTS, ["requests.api.get"])
    assert (reexport["status"], reexport["reason"]) == (engine.UNKNOWN, engine.SYMBOL_MATCH_UNCERTAIN)
    assert evaluate(graph, torch, ["torch.load", "torch.jit.load"])["status"] == engine.REACHABLE          # an exact match still wins


def test_affected_names_not_written_with_the_import_name_cannot_be_compared():
    pillow = dependency("pillow", "9.0", display="Pillow")
    graph = graph_of({"x.py": "from PIL import Image\n\ndef run(p):\n    return Image.open(p)\n"}, dependencies=[pillow])
    result = evaluate(graph, pillow, ["Image.open"])
    assert (result["status"], result["reason"]) == (engine.UNKNOWN, engine.SYMBOL_MATCH_UNCERTAIN) and "PIL" in result["explanation"]
    assert evaluate(graph, pillow, ["PIL.Image.open"])["status"] == engine.REACHABLE


def test_an_unexplained_import_prevents_concluding_that_a_package_is_never_imported():
    msgpack = dependency("msgpack-python", "0.5")
    graph = graph_of({"x.py": "import msgpack\n\ndef run(b):\n    return msgpack.unpackb(b)\n"}, dependencies=[msgpack, REQUESTS])
    result = evaluate(graph, msgpack, ["msgpack.unpackb"])
    assert (result["status"], result["reason"], result["confidence"]) == (engine.UNKNOWN, engine.IMPORT_MAPPING_UNKNOWN, None)
    assert result["unmapped_imports"] == ["msgpack"] and "msgpack" in result["explanation"]
    assert graph.stats["mapping"]["unmapped_imports"] == ["msgpack"]
    # With every import explained, the same absence is a result.
    assert evaluate(graph_of(REACHABLE_REPO), PYYAML, ["yaml.load"])["status"] == engine.NOT_CONFIRMED_REACHABLE


def test_an_import_name_shared_by_two_packages_is_unknown_for_both():
    first, second = dependency("opencv-python", "4.8"), dependency("opencv-python-headless", "4.8")
    graph = graph_of({"x.py": "import cv2\n\ndef run(p):\n    return cv2.imread(p)\n"}, dependencies=[first, second])
    for package in (first, second):
        result = evaluate(graph, package, ["cv2.imread"])
        assert (result["status"], result["reason"]) == (engine.UNKNOWN, engine.AMBIGUOUS_DEPENDENCY)


def test_a_module_does_not_satisfy_its_own_absolute_import():
    celery = dependency("celery", "5.3")
    graph = graph_of({"proj/__init__.py": "", "proj/celery.py": "from celery import Celery\n\napp = Celery('proj')\n"}, dependencies=[celery])
    assert [(e["source"], e["target"]) for e in edges(graph, kind="calls")] == [("proj.celery", "ext:celery.Celery")]
    assert evaluate(graph, celery, ["celery.Celery"])["status"] == engine.REACHABLE


def test_a_local_module_with_a_dependencys_import_name_makes_that_dependency_unknown():
    graph = graph_of({"app/util/yaml.py": "def load(t):\n    return t\n", "app/util/loader.py": "import yaml\n\ndef run(t):\n    return yaml.load(t)\n"})
    assert graph.stats["mapping"]["shadowed_dependency_node_ids"] == ["pypi:pyyaml@5.1"]
    assert graph.imports[0]["shadows_dependency"] is True
    result = evaluate(graph, PYYAML, ["yaml.load"])
    assert (result["status"], result["reason"]) == (engine.UNKNOWN, engine.AMBIGUOUS_DEPENDENCY)


def test_a_name_imported_on_two_branches_reaches_both_packages_at_reduced_confidence():
    ujson, simplejson = dependency("ujson", "5.0"), dependency("simplejson", "3.0")
    graph = graph_of({"x.py": """
        try:
            import ujson as json
        except ImportError:
            import simplejson as json

        def handle(text):
            return json.loads(text)
    """}, dependencies=[ujson, simplejson])
    for package, name in ((ujson, "ujson.loads"), (simplejson, "simplejson.loads")):
        result = evaluate(graph, package, [name])
        assert (result["status"], result["confidence"]) == (engine.REACHABLE, MEDIUM), name
        assert "more than one way" in result["path"]["edges"][-1]["basis"]


def test_star_import_chains_are_resolved_once_and_loops_end():
    import time
    files = {f"m{i}.py": f"from m{i + 1} import *\nfrom m{i + 1} import *\n" for i in range(60)}
    files["m60.py"] = "def real():\n    return 1\n"
    files["main.py"] = "from m0 import nothing, real\nnothing()\nreal()\n"
    started = time.monotonic()
    graph = graph_of(files)
    assert time.monotonic() - started < 5
    assert [e["target"] for e in edges(graph, kind="calls")] == ["m60:real"]
    assert [u["reason"] for u in graph.unresolved] == [callgraph.LOCAL_SYMBOL_NOT_FOUND]
    loop = graph_of({"a.py": "from b import *\n", "b.py": "from a import *\n", "c.py": "from a import thing\nthing()\n"})
    assert edges(loop, kind="calls") == [] and [u["reason"] for u in loop.unresolved] == [callgraph.LOCAL_SYMBOL_NOT_FOUND]


def test_long_dotted_names_do_not_make_module_lookup_expensive():
    import time
    deep = "a/b/c/d/e/f/x.py"
    source = "import pkg\n" + "".join("pkg" + ".attr" * 24 + "()\n" for _ in range(400))
    started = time.monotonic()
    graph = graph_of({deep: source, "pkg/__init__.py": ""})
    assert time.monotonic() - started < 5 and graph.stats["unresolved"] == 400


def test_the_resolution_budget_stops_runaway_work_and_marks_the_graph_incomplete():
    builder = callgraph.GraphBuilder(
        [ANALYZERS["python"].parse("x.py", b"import requests\n" + b"requests.get('u')\n" * 50, SourceLimits())], DependencyIndex(DEPENDENCIES))
    builder.max_steps = 10
    graph = builder.build()
    assert graph.truncated is True and graph.stats["truncated"] is True


def test_graph_building_checks_the_deadline_between_modules():
    calls = []

    def check():
        calls.append(1)
        if len(calls) == 2:
            raise TimeoutError("deadline")
    parsed = [ANALYZERS["python"].parse(f"m{i}.py", b"x = 1\n", SourceLimits()) for i in range(5)]
    with pytest.raises(TimeoutError):
        build_graph(parsed, DependencyIndex(DEPENDENCIES), check=check)

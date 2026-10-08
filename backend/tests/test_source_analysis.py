"""Source inventory and the Python AST analyzer (pure functions; nothing is fetched, imported or executed)."""

import sys
import textwrap

import pytest

from app.analyzers.source import ANALYZERS, SourceAnalyzer, SourceLimits, base, inventory

PYTHON = ANALYZERS["python"]
LIMITS = inventory.InventoryLimits(max_files=100, max_file_bytes=10_000, max_total_bytes=100_000)


def parse(source: str, path: str = "app/services/user.py", limits: SourceLimits | None = None):
    return PYTHON.parse(path, textwrap.dedent(source).encode(), limits or SourceLimits())


def usages(result, usage=None, caller=None):
    return [u for u in result.usages if (usage is None or u["usage"] == usage) and (caller is None or u["caller"].endswith(caller))]


def targets(result, **filters):
    return [u["target"] for u in usages(result, **filters)]


def listing(*paths, size=100):
    return [{"path": p, "size": size, "sha": "a" * 40} for p in paths]


def selection(entries):
    return {e["path"]: e["selection"] for e in entries}


# --- analyzer contract --------------------------------------------------------------------

def test_python_is_the_supported_language_behind_a_language_neutral_interface():
    assert sorted(ANALYZERS) == ["python"]
    assert isinstance(PYTHON, SourceAnalyzer) and PYTHON.extensions == (".py",)


@pytest.mark.parametrize("path,module", [
    ("app/services/user.py", "app.services.user"),
    ("app/__init__.py", "app"),
    ("main.py", "main"),
    ("backend/app/core/__init__.py", "backend.app.core"),
])
def test_module_identity_is_the_repository_path(path, module):
    assert PYTHON.module_name(path) == module


# --- symbols ------------------------------------------------------------------------------

SERVICE = """
    import functools

    def create_user(name):
        return name

    async def fetch_user(user_id):
        return user_id

    @functools.total_ordering
    class UserService(BaseService, metaclass=Meta):
        retries = 3

        def create_user(self, name):
            def normalise(value):
                return value.strip()
            return normalise(name)

        @staticmethod
        def build():
            return UserService()

        class Meta:
            pass
"""


def test_functions_classes_and_methods_get_stable_identities():
    result = parse(SERVICE)
    assert result.status == base.PARSED and result.language == "python" and result.module == "app.services.user"
    kinds = {s["id"]: s["kind"] for s in result.symbols}
    assert kinds == {
        "app.services.user": "module",
        "app.services.user:create_user": "function",
        "app.services.user:fetch_user": "function",
        "app.services.user:UserService": "class",
        "app.services.user:UserService.create_user": "method",
        "app.services.user:UserService.create_user.<locals>.normalise": "function",
        "app.services.user:UserService.build": "method",
        "app.services.user:UserService.Meta": "class",
    }
    assert parse(SERVICE).symbols == result.symbols                         # deterministic


def test_symbols_carry_source_locations_parents_decorators_and_bases():
    by_id = {s["id"]: s for s in parse(SERVICE).symbols}
    function = by_id["app.services.user:create_user"]
    assert (function["line"], function["end_line"], function["col"], function["path"]) == (4, 5, 0, "app/services/user.py")
    assert function["parent"] == "app.services.user" and function["name"] == "create_user"
    service = by_id["app.services.user:UserService"]
    assert service["decorators"] == ["functools.total_ordering"] and service["bases"] == ["BaseService"]
    method = by_id["app.services.user:UserService.create_user"]
    assert method["parent"] == "app.services.user:UserService" and method["qualname"] == "UserService.create_user" and method["col"] == 4
    assert by_id["app.services.user:UserService.build"]["decorators"] == ["staticmethod"]


# --- imports ------------------------------------------------------------------------------

def test_every_import_form_is_extracted_with_its_statement_and_location():
    result = parse("""
        import requests
        import os.path
        import numpy as np
        from requests import get
        from requests.adapters import HTTPAdapter as Adapter
        from . import util
        from ..core.db import connect
        from legacy import *

        def late():
            import json
    """)
    rows = [(i["module"], i["name"], i["bound"], i["level"], i["star"], i["line"], i["scope"].split(":")[-1]) for i in result.imports]
    assert rows == [
        ("requests", None, "requests", 0, False, 2, "app.services.user"),
        ("os.path", None, "os", 0, False, 3, "app.services.user"),
        ("numpy", None, "np", 0, False, 4, "app.services.user"),
        ("requests", "get", "get", 0, False, 5, "app.services.user"),
        ("requests.adapters", "HTTPAdapter", "Adapter", 0, False, 6, "app.services.user"),
        ("", "util", "util", 1, False, 7, "app.services.user"),
        ("core.db", "connect", "connect", 2, False, 8, "app.services.user"),
        ("legacy", None, None, 0, True, 9, "app.services.user"),
        ("json", None, "json", 0, False, 12, "late"),
    ]
    assert result.imports[4]["statement"] == "from requests.adapters import HTTPAdapter as Adapter"
    assert all(i["dynamic"] is False for i in result.imports)


# --- calls --------------------------------------------------------------------------------

def test_calls_are_bound_to_what_the_name_was_imported_as():
    result = parse("""
        import requests
        import requests as req
        from requests import get, Session as S

        def fetch(url):
            a = requests.get(url)
            b = req.post(url)
            c = get(url)
            return S()
    """)
    assert targets(result, usage="call", caller=":fetch") == [
        {"kind": "import", "module": "requests", "name": None, "level": 0, "attrs": ["get"]},
        {"kind": "import", "module": "requests", "name": None, "level": 0, "attrs": ["post"]},
        {"kind": "import", "module": "requests", "name": "get", "level": 0, "attrs": []},
        {"kind": "import", "module": "requests", "name": "Session", "level": 0, "attrs": []},
    ]
    first = usages(result, usage="call", caller=":fetch")[0]
    assert (first["line"], first["col"], first["text"]) == (7, 8, "a = requests.get(url)")


def test_calls_to_local_functions_classes_and_methods_on_self():
    result = parse("""
        def helper():
            return 1

        class Service:
            def run(self):
                self.step()
                self.inherited()
                self.client.send()
                return helper(), Service()

            def step(self):
                return helper()

            @classmethod
            def make(cls):
                return cls.step
    """)
    run = targets(result, usage="call", caller="Service.run")
    assert {"kind": "local", "symbol": "app.services.user:Service.step", "attrs": [], "via": "self"} in run
    assert {"kind": "local", "symbol": "app.services.user:helper", "attrs": []} in run
    assert {"kind": "local", "symbol": "app.services.user:Service", "attrs": []} in run
    reasons = sorted(t["reason"] for t in run if t["kind"] == "unresolved")
    assert reasons == [base.SELF_ATTRIBUTE, base.SELF_ATTRIBUTE]             # a method the class does not define; self.client.send()
    assert targets(result, caller="Service.make")[0]["via"] == "self"        # cls.step: bound the same way as self.step


def test_python_scoping_decides_which_binding_a_name_refers_to():
    result = parse("""
        import requests

        def shadowed(requests):
            return requests.get("u")              # the parameter, not the module

        def reassigned():
            get = requests.get
            get = other
            return get("u")                       # bound twice: not known

        def nested():
            def inner():
                return requests.get("u")          # found in the enclosing module scope
            return inner()

        def comprehension(items):
            return [requests(i) for requests in items], (lambda requests: requests.get(1))
    """)
    assert targets(result, usage="call", caller=":shadowed")[0]["reason"] == base.UNKNOWN_RECEIVER
    assert targets(result, usage="call", caller=":reassigned")[0]["reason"] == base.UNKNOWN_RECEIVER
    assert targets(result, usage="call", caller="inner")[0] == {"kind": "import", "module": "requests", "name": None, "level": 0, "attrs": ["get"]}
    assert targets(result, usage="call", caller=":nested")[0]["symbol"].endswith("nested.<locals>.inner")
    assert [t["kind"] for t in targets(result, usage="call", caller=":comprehension")] == ["unresolved", "unresolved"]


def test_single_assignments_are_followed_as_aliases_and_instances_and_marked_as_inferred():
    result = parse("""
        import requests
        from requests import Session

        client = Session()
        send = requests.post

        def use(url):
            with requests.Session() as s:
                s.get(url)
            response = requests.get(url)
            response.json()
            return client.send(url), send(url), requests.Session().head(url)
    """)
    found = {(tuple(t["attrs"]), t.get("via")) for t in targets(result, usage="call", caller=":use") if t["kind"] == "import"}
    assert (("Session", "get"), "instance") in found                         # with ... as s
    assert (("get", "json"), "instance") in found                            # attribute of a call result
    assert (("send",), "instance") in found                                  # module-level client = Session()
    assert (("post",), "alias") in found                                     # send = requests.post
    assert (("Session", "head"), "instance") in found                        # chained call
    assert (("get",), None) in found                                         # the direct call carries no inference


def test_references_and_decorators_are_recorded_separately_from_calls():
    result = parse("""
        import requests
        from flask import Flask, login_required

        app = Flask(__name__)

        @app.route("/x")
        @login_required
        def view():
            return list(map(requests.get, ["u"])), dict(callback=requests.post)
    """)
    assert [(t["module"], t["name"]) for t in targets(result, usage="decorator")] == [("flask", "login_required")]
    assert [t["attrs"] for t in targets(result, usage="reference", caller=":view")] == [["get"], ["post"]]
    route = [u for u in usages(result, usage="call") if u["line"] == 7]
    assert route[0]["caller"] == "app.services.user" and route[0]["target"]["via"] == "instance"   # evaluated at module level


def test_dynamic_constructs_are_reported_as_unresolved_with_a_reason():
    result = parse("""
        from plugins import *
        import importlib
        import requests

        def run(name, obj, code):
            getattr(requests, name)("u")
            getattr(obj, "fixed")()
            importlib.import_module(name)
            __import__(name)
            eval(code)
            exec(code)
            obj.method()
            handlers[name]()
            from_star()
            undefined_thing()
    """)
    by_reason = {}
    for target in targets(result, usage="call", caller=":run"):
        if target["kind"] == "unresolved":
            by_reason.setdefault(target["reason"], []).append(target)
    assert len(by_reason[base.DYNAMIC_GETATTR]) == 1
    assert by_reason[base.DYNAMIC_GETATTR][0]["subject"] == {"kind": "import", "module": "requests", "name": None, "level": 0, "attrs": []}
    assert len(by_reason[base.DYNAMIC_IMPORT]) == 2 and len(by_reason[base.DYNAMIC_EVAL]) == 2
    assert len(by_reason[base.STAR_IMPORT]) == 2                              # names a star import could supply
    assert base.UNKNOWN_RECEIVER in by_reason and base.CALL_RESULT in by_reason
    assert not [t for t in targets(result, caller=":run") if t["kind"] == "import" and t["attrs"]]   # nothing was guessed


def test_literal_dynamic_access_is_as_explicit_as_the_static_form():
    result = parse("""
        import importlib
        import requests

        def run():
            getattr(requests, "get")("u")
            importlib.import_module("yaml")
    """)
    calls = targets(result, usage="call", caller=":run")
    assert {"kind": "import", "module": "requests", "name": None, "level": 0, "attrs": ["get"]} in calls
    dynamic = [i for i in result.imports if i["dynamic"]]
    assert [(i["module"], i["line"], i["scope"]) for i in dynamic] == [("yaml", 7, "app.services.user:run")]


def test_undefined_names_are_not_resolved_and_builtins_are_not_dependencies():
    result = parse("""
        def run(values):
            print(len(values))
            return missing(values)
    """)
    kinds = [(t["kind"], t.get("name") or t.get("reason")) for t in targets(result, caller=":run")]
    assert kinds == [("builtin", "print"), ("builtin", "len"), ("unresolved", base.UNDEFINED_NAME)]


def test_names_bound_in_a_class_body_are_not_resolved_as_module_names():
    result = parse("""
        import requests

        class Model:
            requests = make_field()
            url = requests.clean()
    """)
    assert [t["reason"] for t in targets(result, usage="call") if t["kind"] == "unresolved"] == [base.UNDEFINED_NAME, base.UNKNOWN_RECEIVER]


# --- hostile and malformed input ----------------------------------------------------------

@pytest.mark.parametrize("content,status", [
    (b"def broken(:\n    pass\n", base.SYNTAX_ERROR),
    (b"print 'python 2'\n", base.SYNTAX_ERROR),
    (b"\x7fELF\x02\x01\x01\x00\x00\x00", base.NOT_TEXT),
    (b"x = 1\x00\n", base.NOT_TEXT),
    (b"# -*- coding: no-such-codec -*-\nx = 1\n", base.NOT_TEXT),
    (b"\xff\xfe\xfd broken utf-8\n", base.NOT_TEXT),
    (b"x = " + b"(" * 5000 + b")" * 5000, base.SYNTAX_ERROR),
    (b"x = " + b"-" * 200_000 + b"1\n", base.TOO_COMPLEX),
])
def test_malformed_and_binary_input_gives_a_status_never_an_exception(content, status):
    result = PYTHON.parse("bad.py", content, SourceLimits())
    assert result.status == status and result.error and len(result.error) <= 300
    assert result.symbols == [] and result.imports == [] and result.usages == []


def test_empty_and_comment_only_files_parse():
    for content in (b"", b"# nothing here\n", b"\n\n"):
        result = PYTHON.parse("empty.py", content, SourceLimits())
        assert result.status == base.PARSED and [s["kind"] for s in result.symbols] == ["module"]


def test_declared_source_encodings_are_honoured():
    result = PYTHON.parse("latin.py", "# -*- coding: latin-1 -*-\nname = 'caf\xe9'\nimport requests\n".encode("latin-1"), SourceLimits())
    assert result.status == base.PARSED and [i["module"] for i in result.imports] == ["requests"]


def test_node_limit_stops_the_analysis_of_one_file():
    result = PYTHON.parse("big.py", b"x = 1\n" * 500, SourceLimits(max_nodes=100))
    assert result.status == base.TOO_COMPLEX and "100" in result.error and result.usages == []


def test_record_limit_keeps_what_fits_and_says_the_result_is_incomplete():
    result = PYTHON.parse("many.py", b"import requests\n" + b"requests.get('u')\n" * 50, SourceLimits(max_records=10))
    assert result.status == base.PARSED and result.truncated is True
    assert len(result.symbols) + len(result.imports) + len(result.usages) == 10


def test_long_lines_are_stored_shortened():
    result = PYTHON.parse("long.py", b"import requests\nrequests.get('" + b"a" * 5000 + b"')\n", SourceLimits())
    assert len(result.usages[0]["text"]) == 200


def test_analysing_source_does_not_execute_or_import_it(tmp_path, monkeypatch):
    marker = tmp_path / "executed"
    monkeypatch.chdir(tmp_path)
    source = f"""
        import os, definitely_not_installed_package_xyz
        open({str(marker)!r}, "w").write("ran")
        os.system("touch {marker}")
        raise SystemExit(3)
    """
    before = set(sys.modules)
    result = parse(source, "evil.py")
    assert result.status == base.PARSED and not marker.exists()
    assert "definitely_not_installed_package_xyz" not in sys.modules and set(sys.modules) == before


# --- inventory ----------------------------------------------------------------------------

def test_inventory_selects_supported_source_and_counts_other_languages():
    files = listing("app/main.py", "app/util.py", "web/index.js", "web/app.tsx", "README.md", "lib/core.go", "logo.png")
    result = inventory.select(files, ANALYZERS, LIMITS)
    assert selection(result["entries"]) == {"app/main.py": inventory.SELECTED, "app/util.py": inventory.SELECTED}
    assert result["other_languages"] == {"Go": 1, "JavaScript": 1, "TypeScript": 1}
    entry = result["entries"][0]
    assert entry == {"path": "app/main.py", "language": "python", "size": 100, "git_blob_sha": "a" * 40, "is_test": False,
                     "selection": inventory.SELECTED}


def test_vendored_and_generated_code_is_skipped_with_a_reason():
    files = listing("app/main.py", "vendor/lib/x.py", "node_modules/pkg/setup.py", ".venv/lib/site-packages/requests/api.py",
                    "env/lib/python3.12/site-packages/x.py", "app/__pycache__/x.py", "proto/service_pb2.py", "proto/service_pb2_grpc.py")
    chosen = selection(inventory.select(files, ANALYZERS, LIMITS)["entries"])
    assert chosen["app/main.py"] == inventory.SELECTED
    assert chosen["proto/service_pb2.py"] == chosen["proto/service_pb2_grpc.py"] == inventory.SKIPPED_GENERATED
    assert {chosen[p] for p in ("vendor/lib/x.py", "node_modules/pkg/setup.py", ".venv/lib/site-packages/requests/api.py",
                                "env/lib/python3.12/site-packages/x.py", "app/__pycache__/x.py")} == {inventory.SKIPPED_IGNORED_DIRECTORY}


def test_directories_that_can_hold_application_code_are_analysed():
    # "build", "dist", "env", "out", "target" and "coverage" are ordinary package names as well as output folders.
    files = listing("app/build/deploy.py", "env/settings.py", "dist/tool.py", "out/report.py", "target/run.py", "coverage/plugin.py")
    assert set(selection(inventory.select(files, ANALYZERS, LIMITS)["entries"]).values()) == {inventory.SELECTED}


def test_python_code_in_formats_that_are_not_parsed_is_listed_as_unread():
    files = listing("analysis.ipynb", "fast/core.pyx", "app/types.pyi", "vendor/x.ipynb", "app/main.py")
    result = inventory.select(files, ANALYZERS, LIMITS)
    assert selection(result["entries"]) == {"analysis.ipynb": inventory.SKIPPED_UNSUPPORTED_FORMAT, "fast/core.pyx": inventory.SKIPPED_UNSUPPORTED_FORMAT,
                                            "app/main.py": inventory.SELECTED}
    assert inventory.SKIPPED_UNSUPPORTED_FORMAT in inventory.INCOMPLETE_REASONS


def test_a_file_above_the_size_limit_is_rejected():
    files = listing("app/main.py") + listing("app/huge.py", size=10_001)
    chosen = selection(inventory.select(files, ANALYZERS, LIMITS)["entries"])
    assert chosen == {"app/main.py": inventory.SELECTED, "app/huge.py": inventory.SKIPPED_TOO_LARGE}


def test_file_and_total_size_limits_keep_application_code_before_tests():
    files = listing("tests/test_a.py", "app/deep/pkg/x.py", "app/main.py", "main.py", "app/test_local.py")
    result = inventory.select(files, ANALYZERS, inventory.InventoryLimits(max_files=3, max_file_bytes=1000, max_total_bytes=10_000))
    assert selection(result["entries"]) == {
        "main.py": inventory.SELECTED, "app/main.py": inventory.SELECTED, "app/deep/pkg/x.py": inventory.SELECTED,
        "app/test_local.py": inventory.SKIPPED_FILE_LIMIT, "tests/test_a.py": inventory.SKIPPED_FILE_LIMIT}
    by_size = inventory.select(files, ANALYZERS, inventory.InventoryLimits(max_files=10, max_file_bytes=1000, max_total_bytes=250))
    assert list(selection(by_size["entries"]).values()).count(inventory.SKIPPED_SIZE_LIMIT) == 3
    assert [e["path"] for e in result["entries"]] == sorted(f["path"] for f in files)     # listed in a stable order


@pytest.mark.parametrize("path", ["../outside.py", "/etc/passwd.py", "app/../../x.py", "app\\win.py", "C:/x.py", "app/\x00.py", "a//b.py"])
def test_paths_that_leave_the_repository_are_never_selected(path):
    result = inventory.select([{"path": path, "size": 10, "sha": "a" * 40}, {"path": "ok.py", "size": 10, "sha": "b" * 40}], ANALYZERS, LIMITS)
    assert selection(result["entries"]) == {path: inventory.SKIPPED_UNSAFE_PATH, "ok.py": inventory.SELECTED}


def test_entries_without_a_blob_id_or_with_junk_fields_are_not_selected():
    result = inventory.select([{"path": "a.py", "size": 10}, {"path": None, "size": 1, "sha": "a" * 40}, {"path": 5}], ANALYZERS, LIMITS)
    assert selection(result["entries"]) == {"a.py": inventory.SKIPPED_UNSAFE_PATH}


@pytest.mark.parametrize("path,expected", [
    ("tests/test_api.py", True), ("app/tests/helpers.py", True), ("test_main.py", True), ("app/client_test.py", True),
    ("conftest.py", True), ("app/main.py", False), ("app/testing_utils.py", False), ("contest/run.py", False),
])
def test_test_code_is_recognised_by_path(path, expected):
    assert inventory.is_test_path(path) is expected


def test_every_way_of_binding_a_name_hides_an_import_of_the_same_name():
    result = parse("""
        import requests

        def annotated():
            requests: object = make()
            return requests.get()

        def augmented():
            requests += 1
            return requests.get()

        def looped(items):
            for requests in items:
                requests.get()

        def unpacked(pair):
            requests, other = pair
            return requests.get()

        def handled():
            try:
                pass
            except Exception as requests:
                requests.get()

        def deleted():
            del requests
            return requests.get()

        def walrus(items):
            if (requests := items):
                return requests.get()

        def with_tuple(a, b):
            with a as (requests, x), b:
                return requests.get()

        def uses_global():
            global requests
            return requests.get("u")
    """)
    for name in ("annotated", "augmented", "looped", "unpacked", "handled", "deleted", "walrus", "with_tuple"):
        found = [t for t in targets(result, usage="call", caller=f":{name}") if t.get("expr", "").startswith("requests.get")]
        assert [t["reason"] for t in found] == [base.UNKNOWN_RECEIVER], name
    assert targets(result, usage="call", caller=":uses_global")[0] == {"kind": "import", "module": "requests", "name": None, "level": 0, "attrs": ["get"]}


def test_calls_inside_nested_blocks_and_expressions_are_found():
    result = parse("""
        import requests

        async def run(items):
            try:
                if items:
                    async with requests.Session() as s:
                        await s.get("u")
                else:
                    while True:
                        requests.post("u")
            except ValueError:
                requests.put("u")
            finally:
                requests.delete("u")
            match items:
                case [first]:
                    requests.head(first)
            return {k: requests.patch(k) for k in items}, f"{requests.options('u')}"
    """)
    names = {t["attrs"][-1] for t in targets(result, usage="call", caller=":run") if t["kind"] == "import"}
    assert names == {"Session", "get", "post", "put", "delete", "head", "patch", "options"}


def test_default_arguments_and_class_headers_are_evaluated_in_the_enclosing_scope():
    result = parse("""
        import requests

        def outer():
            def inner(session=requests.Session()):
                return session
            class Local(requests.Base, metaclass=requests.Meta):
                pass
            return inner
    """)
    callers = {(u["caller"].split(":")[-1], tuple(u["target"]["attrs"])) for u in result.usages if u["target"]["kind"] == "import"}
    assert callers == {("outer", ("Session",)), ("outer", ("Base",)), ("outer", ("Meta",))}


# --- names bound in more than one way (review findings) ------------------------------------

def test_a_name_imported_on_two_branches_is_recorded_for_both_and_marked_uncertain():
    result = parse("""
        try:
            import ujson as json
        except ImportError:
            import simplejson as json

        def handle(text):
            return json.loads(text)
    """)
    found = targets(result, usage="call", caller=":handle")
    assert sorted((t["module"], t["via"], t["attrs"][0]) for t in found) == [("simplejson", "conditional", "loads"), ("ujson", "conditional", "loads")]
    assert all("alternatives" not in t for t in found)


def test_an_import_with_a_fallback_assignment_is_uncertain_not_dropped():
    result = parse("""
        try:
            import yaml
        except ImportError:
            yaml = None

        def load(text):
            return yaml.safe_load(text)
    """)
    assert targets(result, usage="call", caller=":load") == [
        {"kind": "import", "module": "yaml", "name": None, "level": 0, "attrs": ["safe_load"], "via": "conditional"}]


def test_a_later_star_import_makes_an_earlier_import_uncertain():
    result = parse("""
        from yaml import load
        from wrappers import *

        def run(text):
            return load(text)
    """)
    assert targets(result, usage="call", caller=":run")[0]["via"] == "conditional"
    earlier = parse("from wrappers import *\nfrom yaml import load\n\ndef run(text):\n    return load(text)\n")
    assert "via" not in targets(earlier, usage="call", caller=":run")[0]


def test_a_module_name_rebound_through_global_is_uncertain():
    result = parse("""
        import yaml

        def setup():
            global yaml
            yaml = SafeWrapper()

        def load(text):
            return yaml.load(text)
    """)
    assert targets(result, usage="call", caller=":load")[0]["via"] == "conditional"


def test_pattern_captures_and_type_parameters_hide_an_import():
    captured = parse("""
        import yaml

        def run(value):
            match value:
                case {"k": yaml}:
                    return yaml.load(1)
                case [*yaml]:
                    return yaml.load(2)
    """)
    assert [t["kind"] for t in targets(captured, usage="call", caller=":run")] == ["unresolved", "unresolved"]
    generic = PYTHON.parse("g.py", b"import yaml\n\ndef run[yaml](x):\n    return yaml.load(x)\n", SourceLimits())
    if generic.status == base.PARSED:                      # PEP 695 syntax needs Python 3.12
        assert [t["kind"] for t in targets(generic, usage="call", caller=":run")] == ["unresolved"]


def test_a_definition_that_is_also_assigned_is_not_resolved():
    result = parse("""
        def handler():
            return 1

        handler = wrap(handler)

        def run():
            return handler()
    """)
    assert targets(result, usage="call", caller=":run")[0]["reason"] == base.UNKNOWN_RECEIVER


def test_very_long_attribute_chains_and_decorator_lists_stay_cheap():
    import time
    started = time.monotonic()
    chain = PYTHON.parse("c.py", b"import a\n" + b"a" + b".b" * 5000 + b"()\n", SourceLimits())
    decorated = PYTHON.parse("d.py", b"@a\n" * 20000 + b"def f(): pass\n", SourceLimits())
    assert time.monotonic() - started < 5
    assert chain.status in (base.PARSED, base.TOO_COMPLEX, base.SYNTAX_ERROR) and decorated.status in (base.PARSED, base.TOO_COMPLEX)
    assert not [u for u in chain.usages if u["target"]["kind"] == "import" and len(u["target"]["attrs"]) > 24]


def test_the_files_own_syntax_warnings_are_not_printed(capsys, recwarn):
    assert PYTHON.parse("w.py", b"x = '\\d'\ny = 1 is 1\n", SourceLimits()).status == base.PARSED
    captured = capsys.readouterr()
    assert captured.err == "" and len(recwarn) == 0

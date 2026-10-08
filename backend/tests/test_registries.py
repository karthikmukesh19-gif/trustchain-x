"""Package registry clients: what is asked, where, and how every kind of answer is normalised.

The registries are served by httpx.MockTransport, so the real client code runs
and no request leaves the process. Package contents here are test data.
"""

import json
from datetime import datetime, timezone

import httpx
import pytest

from app.collectors.registries import build_registries
from app.collectors.registries.base import COLLECTED, COMPACT, ERROR, FULL, INVALID_NAME, NOT_FOUND, parse_time
from app.config.settings import SettingsError, load_settings
from tests.conftest import TEST_ENV, RegistryStub


def clients(stub, **env):
    registries = build_registries(load_settings({**TEST_ENV, **env}), httpx.MockTransport(stub.handler))
    for client in registries.values():
        client.sleep = lambda _seconds: None
    return registries


@pytest.fixture
def stub():
    stub = RegistryStub()
    stub.add("pypi", "requests", "2.32.3", {"2.19.1": "2018-06-14T13:40:38.000000Z", "2.31.0": "2023-05-22T15:12:42.313790Z",
                                            "2.32.3": "2024-05-29T15:37:47.000000Z", "2.32.0": "2024-05-20T15:00:00.000000Z",
                                            "0.0.1": None}, yanked=["2.32.0"])
    stub.add("npm", "lodash", "4.17.21", {"4.17.20": "2020-08-13T16:53:54.152Z", "4.17.21": "2021-02-20T15:42:16.891Z",
                                          "1.0.0": "2013-02-18T00:00:00.000Z"}, deprecated=["1.0.0"])
    stub.add("npm", "@babel/core", "7.24.0", {"7.24.0": "2024-02-28T12:00:00.000Z"})
    return stub


# --- PyPI -------------------------------------------------------------------------------------

def test_pypi_release_dates_latest_and_yanked_come_from_the_registry(stub):
    result = clients(stub)["pypi"].lookup("requests")
    assert result["status"] == COLLECTED and result["detail"] == FULL and result["registry"] == "pypi"
    assert result["latest_version"] == "2.32.3"
    assert result["latest_published_at"] == datetime(2024, 5, 29, 15, 37, 47, tzinfo=timezone.utc)
    assert result["versions"]["2.19.1"] == datetime(2018, 6, 14, 13, 40, 38, tzinfo=timezone.utc)
    assert result["withdrawn_versions"] == ["2.32.0"]
    assert result["source_url"] == "https://pypi.org/pypi/requests/json"
    assert str(stub.requests[0].url) == "https://pypi.org/pypi/requests/json" and stub.requests[0].method == "GET"


def test_a_release_without_files_has_no_date_rather_than_an_invented_one(stub):
    result = clients(stub)["pypi"].lookup("requests")
    assert "0.0.1" in result["versions"] and result["versions"]["0.0.1"] is None
    assert "0.0.1" not in result["withdrawn_versions"]


def test_pypi_uses_the_earliest_file_of_a_release(stub):
    stub.raw["/pypi/multi/"] = json.dumps({"info": {"version": "1.0"}, "releases": {"1.0": [
        {"upload_time_iso_8601": "2020-03-02T00:00:00Z"}, {"upload_time_iso_8601": "2020-03-01T00:00:00Z"},
        {"upload_time_iso_8601": "not a date"}, "junk"]}}).encode()
    assert clients(stub)["pypi"].lookup("multi")["versions"]["1.0"] == datetime(2020, 3, 1, tzinfo=timezone.utc)


def test_pypi_package_that_does_not_exist(stub):
    result = clients(stub)["pypi"].lookup("no-such-package")
    assert result["status"] == NOT_FOUND and result["latest_version"] is None and result["versions"] == {}


@pytest.mark.parametrize("name", ["", "../../etc/passwd", "a/b", "requests?x=1", "requests#f", "a b", "-lead", "Requests", "a" * 300,
                                  "x\n", "%2e%2e", "requests/../../simple", None, 7])
def test_pypi_names_that_could_not_be_packages_are_never_requested(stub, name):
    result = clients(stub)["pypi"].lookup(name)
    assert result["status"] == INVALID_NAME and stub.requests == []


# --- npm --------------------------------------------------------------------------------------

def test_npm_full_document_has_dates_and_deprecations(stub):
    result = clients(stub)["npm"].lookup("lodash", FULL)
    assert result["status"] == COLLECTED and result["detail"] == FULL and result["latest_version"] == "4.17.21"
    assert result["latest_published_at"] == datetime(2021, 2, 20, 15, 42, 16, 891000, tzinfo=timezone.utc)
    assert set(result["versions"]) == {"4.17.20", "4.17.21", "1.0.0"}                # "created" is not a version
    # A deprecated npm version is still published: it is reported as deprecated, never as withdrawn.
    assert result["deprecated_versions"] == ["1.0.0"] and result["withdrawn_versions"] == [] and result["deprecated"] is False
    assert stub.requests[0].headers["accept"] == "application/json"


def test_npm_compact_document_has_versions_but_no_dates(stub):
    result = clients(stub)["npm"].lookup("lodash", COMPACT)
    assert result["status"] == COLLECTED and result["detail"] == COMPACT and result["latest_version"] == "4.17.21"
    assert result["latest_published_at"] is None and set(result["versions"].values()) == {None}
    assert "vnd.npm.install-v1" in stub.requests[0].headers["accept"]


def test_npm_scoped_names_are_one_encoded_path_segment(stub):
    result = clients(stub)["npm"].lookup("@babel/core")
    assert result["status"] == COLLECTED and result["latest_version"] == "7.24.0"
    assert stub.requests[0].url.raw_path == b"/@babel%2Fcore" and stub.requests[0].url.host == "registry.npmjs.org"


def test_npm_package_without_a_latest_tag(stub):
    stub.add("npm", "untagged", None, {"1.0.0": "2020-01-01T00:00:00.000Z"})
    result = clients(stub)["npm"].lookup("untagged")
    assert result["status"] == COLLECTED and result["latest_version"] is None and result["deprecated"] is None


@pytest.mark.parametrize("name", ["", "../x", "a/b/c", "@scope", "@scope/", "@/name", "lodash?x", "lodash#x", "lo dash", ".hidden",
                                  "@a/b/c", "@SCOPE/name", "a" * 215, "lodash/../x", "@scope/..%2f", None])
def test_npm_names_that_could_not_be_packages_are_never_requested(stub, name):
    result = clients(stub)["npm"].lookup(name)
    assert result["status"] == INVALID_NAME and stub.requests == []


# --- failures ---------------------------------------------------------------------------------

@pytest.mark.parametrize("registry,name", [("pypi", "requests"), ("npm", "lodash")])
@pytest.mark.parametrize("status,code,attempts", [(500, "HTTP_ERROR", 2), (503, "HTTP_ERROR", 2), (429, "RATE_LIMITED", 2),
                                                  (403, "HTTP_ERROR", 1), (301, "HTTP_ERROR", 1), (302, "HTTP_ERROR", 1)])
def test_http_failures_are_errors_with_a_code_and_no_values(stub, registry, name, status, code, attempts):
    stub.fail[name] = status
    result = clients(stub)[registry].lookup(name)
    assert result["status"] == ERROR and result["error_code"] == code
    assert result["latest_version"] is None and result["versions"] == {} and len(stub.requests) == attempts


def test_redirects_are_not_followed(stub):
    def redirect(request):
        stub.requests.append(request)
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"})

    registries = build_registries(load_settings(TEST_ENV), httpx.MockTransport(redirect))
    assert registries["pypi"].lookup("requests")["status"] == ERROR
    assert [r.url.host for r in stub.requests] == ["pypi.org"]


@pytest.mark.parametrize("error,code", [(httpx.ReadTimeout("slow"), "TIMEOUT"), (httpx.ConnectError("down"), "UNREACHABLE")])
def test_network_failures(stub, error, code):
    stub.error = error
    for registry, name in (("pypi", "requests"), ("npm", "lodash")):
        result = clients(stub)[registry].lookup(name)
        assert result["status"] == ERROR and result["error_code"] == code and result["versions"] == {}


@pytest.mark.parametrize("body", [b"<html>", b"", b"[]", b"null", b'"text"', b'{"info": 1}', b'{"versions": [], "dist-tags": {}}',
                                  b'{"info": {}, "releases": []}', b"[" * 100_000])
def test_answers_that_are_not_the_expected_document_are_bad_responses(stub, body):
    stub.raw["requests"] = body
    stub.raw["lodash"] = body
    assert clients(stub)["pypi"].lookup("requests")["error_code"] == "BAD_RESPONSE"
    assert clients(stub)["npm"].lookup("lodash")["error_code"] == "BAD_RESPONSE"


def test_an_answer_larger_than_the_limit_is_refused(stub):
    stub.raw["requests"] = json.dumps({"info": {"version": "1"}, "releases": {}, "pad": "x" * 5000}).encode()
    result = clients(stub, PACKAGE_METADATA_MAX_BYTES="2048")["pypi"].lookup("requests")
    assert result["status"] == ERROR and result["error_code"] == "RESPONSE_TOO_LARGE"


def test_hostile_field_values_are_dropped_not_stored(stub):
    stub.raw["requests"] = json.dumps({"info": {"version": "9" * 500}, "releases": {
        "1.0": [{"upload_time_iso_8601": "9999-01-01T00:00:00Z"}], "v" * 500: [], "2.0": [{"upload_time_iso_8601": 12}], "3.0": "x"}}).encode()
    result = clients(stub)["pypi"].lookup("requests")
    assert result["status"] == COLLECTED and result["latest_version"] is None
    assert result["versions"] == {"1.0": None, "2.0": None, "3.0": None}


def test_version_lists_are_capped(stub, monkeypatch):
    from app.collectors.registries import npm, pypi

    monkeypatch.setattr(pypi, "MAX_VERSIONS", 3)
    monkeypatch.setattr(npm, "MAX_VERSIONS", 3)
    stub.add("pypi", "many", "5", {str(n): None for n in range(10)})
    stub.add("npm", "many", "5", {str(n): None for n in range(10)})
    for registry in ("pypi", "npm"):
        result = clients(stub)[registry].lookup("many")
        assert len(result["versions"]) == 3 and result["versions_truncated"] is True


@pytest.mark.parametrize("value,expected", [
    ("2024-05-29T15:37:47Z", datetime(2024, 5, 29, 15, 37, 47, tzinfo=timezone.utc)),
    ("2024-05-29T15:37:47", datetime(2024, 5, 29, 15, 37, 47, tzinfo=timezone.utc)),
    ("1970-01-01T00:00:00Z", None), ("9999-01-01T00:00:00Z", None), ("yesterday", None), ("", None), (None, None), (1716996000, None),
    ("2" * 60, None),
])
def test_dates_are_parsed_or_absent(value, expected):
    assert parse_time(value) == expected


# --- configuration: where the platform may connect ----------------------------------------------

def test_default_registries_and_hosts():
    registries = build_registries(load_settings(TEST_ENV))
    assert {name: client.base_url for name, client in registries.items()} == {"pypi": "https://pypi.org", "npm": "https://registry.npmjs.org"}


def test_registries_can_be_disabled():
    assert build_registries(load_settings({**TEST_ENV, "PACKAGE_METADATA_PROVIDERS": ""})) == {}
    assert list(build_registries(load_settings({**TEST_ENV, "PACKAGE_METADATA_PROVIDERS": "npm"}))) == ["npm"]


@pytest.mark.parametrize("env", [
    {"PYPI_API_URL": "https://evil.example"}, {"NPM_REGISTRY_URL": "https://evil.example"},
    {"PYPI_API_URL": "http://pypi.org"}, {"PYPI_API_URL": "https://pypi.org@evil.example"},
    {"PYPI_API_URL": "https://169.254.169.254"}, {"NPM_REGISTRY_URL": "https://localhost"},
    {"PYPI_API_URL": "https://pypi.org/path?x=1"}, {"NPM_REGISTRY_URL": "file:///etc/passwd"},
    {"PYPI_API_URL": "https://user:pw@pypi.org"}, {"PACKAGE_METADATA_PROVIDERS": "pypi,rubygems"},
    {"PACKAGE_METADATA_TIMEOUT_SECONDS": "0"}, {"INTELLIGENCE_MAX_NODES": "1"}, {"INTELLIGENCE_HISTORY_LIMIT": "0"},
])
def test_unsafe_or_unknown_configuration_is_refused_at_startup(env):
    with pytest.raises(SettingsError):
        load_settings({**TEST_ENV, **env})


def test_a_host_must_be_allow_listed_explicitly():
    with pytest.raises(SettingsError):
        load_settings({**TEST_ENV, "NPM_REGISTRY_URL": "https://npm.internal.example"})
    settings = load_settings({**TEST_ENV, "NPM_REGISTRY_URL": "https://npm.internal.example",
                              "PACKAGE_METADATA_ALLOWED_HOSTS": "pypi.org,npm.internal.example"})
    assert build_registries(settings)["npm"].base_url == "https://npm.internal.example"


def test_a_disabled_registrys_url_is_not_validated():
    settings = load_settings({**TEST_ENV, "PACKAGE_METADATA_PROVIDERS": "pypi", "NPM_REGISTRY_URL": "https://unused.example"})
    assert list(build_registries(settings)) == ["pypi"]


# --- regression tests from the independent review ----------------------------------------------

def test_npm_names_are_requested_exactly_as_given_because_case_distinguishes_packages(stub):
    stub.add("npm", "JSONStream", "1.3.5", {"1.3.5": "2018-10-13T00:00:00.000Z"})
    stub.add("npm", "jsonstream", "9.9.9", {"9.9.9": "2020-01-01T00:00:00.000Z"})          # a different package
    registry = clients(stub)["npm"]
    assert registry.lookup_name({"name": "JSONStream", "normalized_name": "jsonstream"}) == "JSONStream"
    assert registry.lookup("JSONStream")["latest_version"] == "1.3.5" and registry.lookup("jsonstream")["latest_version"] == "9.9.9"
    assert [r.url.raw_path for r in stub.requests] == [b"/JSONStream", b"/jsonstream"]
    assert clients(stub)["pypi"].lookup_name({"name": "PyYAML", "normalized_name": "pyyaml"}) == "pyyaml"     # PyPI names are case-insensitive


@pytest.mark.parametrize("registry", ["pypi", "npm"])
def test_a_capped_version_list_keeps_the_newest_entries_and_always_the_latest(stub, monkeypatch, registry):
    from app.collectors.registries import npm, pypi

    monkeypatch.setattr(pypi, "MAX_VERSIONS", 3)
    monkeypatch.setattr(npm, "MAX_VERSIONS", 3)
    listed = {f"1.{n}.0": f"2020-01-{n + 1:02d}T00:00:00.000Z" for n in range(10)}
    stub.add(registry, "many", "1.9.0", listed)
    newest = clients(stub)[registry].lookup("many")
    assert list(newest["versions"]) == ["1.7.0", "1.8.0", "1.9.0"] and newest["versions_truncated"] is True
    assert newest["latest_published_at"] == datetime(2020, 1, 10, tzinfo=timezone.utc)
    stub.add(registry, "many", "1.0.0", listed)                                             # the registry's latest is its oldest entry
    oldest = clients(stub)[registry].lookup("many")
    assert set(oldest["versions"]) == {"1.0.0", "1.8.0", "1.9.0"} and oldest["latest_published_at"] == datetime(2020, 1, 1, tzinfo=timezone.utc)


def test_dates_are_kept_at_the_precision_the_database_stores():
    assert parse_time("2024-05-29T15:37:47.175627Z") == datetime(2024, 5, 29, 15, 37, 47, 175000, tzinfo=timezone.utc)

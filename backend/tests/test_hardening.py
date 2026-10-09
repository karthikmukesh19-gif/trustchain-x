"""Security checks across the whole API surface, and on what the repository itself ships.

These are written against the application as a whole, so an endpoint added
later is covered without anyone remembering to add it here.
"""

import json
import re
import subprocess
from pathlib import Path

import pytest

from app.config.settings import SettingsError, load_settings
from tests.conftest import TEST_ENV
from tests.pipeline import (  # noqa: F401 - fixtures
    FAKE_TOKEN, advisories, created, evidence_layers, packages, repo, run_layers,
)
from tests.test_intelligence import settings  # noqa: F401

ROOT = Path(__file__).resolve().parents[2]
PUBLIC = {"/api/health", "/api/health/ready", "/api/auth/register", "/api/auth/login"}
OBJECT_ID = "0" * 24


def api_routes(app):
    """Every API operation, read from the generated OpenAPI document (the full, flattened route table)."""
    found = {(path, method.upper()) for path, operations in app.openapi()["paths"].items()
             for method in operations if method.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"} and path.startswith("/api/")}
    assert len(found) > 60, "the route inventory is unexpectedly small"
    return sorted(found)


def fill(path, project_id=OBJECT_ID):
    filled = path.replace("{project_id}", project_id)
    return re.sub(r"\{[a-z_]+\}", OBJECT_ID, filled)


def test_the_route_inventory_includes_every_layer(app):
    paths = {path for path, _method in api_routes(app)}
    for expected in ("/api/projects/{project_id}/attack-paths/analyze", "/api/projects/{project_id}/attack-paths/graph",
                     "/api/projects/{project_id}/maintainers/{maintainer_id}", "/api/projects/{project_id}/commits/{sha}",
                     "/api/projects/{project_id}/security-events", "/api/projects/{project_id}/ai-analysis/{finding_id}",
                     "/api/projects/{project_id}/datasets/{dataset_id}/quality", "/api/projects/{project_id}/trust/explanation",
                     "/api/projects/{project_id}/trust/compare", "/api/projects/{project_id}/overview", "/api/projects/{project_id}/report"):
        assert expected in paths, expected
    assert len(paths) > 60


def test_every_route_except_health_and_sign_in_requires_authentication(client, app):
    unauthenticated = []
    for path, method in api_routes(app):
        if path in PUBLIC:
            continue
        response = client.request(method, fill(path), json={} if method in ("POST", "PUT", "PATCH") else None)
        if response.status_code != 401:
            unauthenticated.append((method, path, response.status_code))
    assert unauthenticated == []


def test_a_forged_or_malformed_token_is_rejected_everywhere(client, app):
    for token in ("", "abc", "Bearer", "a.b.c", "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."):
        for path, method in api_routes(app)[::7]:
            if path in PUBLIC:
                continue
            response = client.request(method, fill(path), headers={"Authorization": f"Bearer {token}"}, json={} if method == "POST" else None)
            assert response.status_code == 401, (method, path, token)


def test_no_project_route_reveals_another_users_project(client, app, auth_headers, other_headers, evidence_layers):
    leaked = []
    for path, method in api_routes(app):
        if "{project_id}" not in path:
            continue
        body = {"enabled": True} if path.endswith("/monitoring") else {} if method in ("POST", "PUT", "PATCH") else None
        response = client.request(method, fill(path, evidence_layers["id"]), headers=other_headers, json=body)
        if response.status_code not in (404, 422):       # 422: a required query parameter is missing, checked before anything is read
            leaked.append((method, path, response.status_code))
        assert "Demo" not in response.text and "octo/intelligence-demo" not in response.text
    assert leaked == []


@pytest.mark.parametrize("identifier", ["{\"$ne\":null}", "$where", "..%2F..%2Fetc%2Fpasswd", "a" * 5000, "%00", "0 OR 1=1", "<script>alert(1)</script>"])
def test_hostile_identifiers_never_reach_a_query_or_cause_an_error(client, app, auth_headers, evidence_layers, identifier):
    for path, method in api_routes(app):
        if method != "GET" or path.count("{") < 2:
            continue
        url = re.sub(r"\{[a-z_]+\}", identifier, path.replace("{project_id}", evidence_layers["id"]))
        response = client.get(url, headers=auth_headers)
        assert response.status_code in (404, 422), (path, response.status_code)
        assert "Traceback" not in response.text and "pymongo" not in response.text.lower()


def test_query_operators_in_parameters_are_treated_as_text(client, auth_headers, evidence_layers):
    base = f"/api/projects/{evidence_layers['id']}"
    for path, params in (("/attack-paths", {"q": "{\"$gt\":\"\"}"}), ("/commits", {"q": ".*"}), ("/maintainers", {"q": "(a+)+$"}),
                         ("/attack-paths", {"q[$ne]": "x"}), ("/commits", {"level[$ne]": "LOW"})):
        response = client.get(base + path, headers=auth_headers, params=params)
        assert response.status_code == 200 and response.json()["total"] in (0, response.json()["total"])
    assert client.get(base + "/commits", headers=auth_headers, params={"q": ".*"}).json()["total"] == 0


def test_security_headers_are_set_on_new_endpoints_and_errors(client, auth_headers, evidence_layers):
    for path in (f"/api/projects/{evidence_layers['id']}/overview", f"/api/projects/{evidence_layers['id']}/report?format=markdown",
                 f"/api/projects/{OBJECT_ID}/trust", "/api/dashboard/evaluation"):
        headers = client.get(path, headers=auth_headers).headers
        assert headers["x-content-type-options"] == "nosniff" and headers["x-frame-options"] == "DENY"
        assert "content-security-policy" in headers and headers["cache-control"] == "no-store"


def test_cors_allows_only_the_configured_origin(client):
    allowed = client.options("/api/projects", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"})
    refused = client.options("/api/projects", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"})
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "access-control-allow-origin" not in refused.headers


def test_internal_errors_do_not_leak_details(client, auth_headers, evidence_layers, monkeypatch):
    from app.services import overview

    def explode(*_args, **_kwargs):
        raise RuntimeError("secret internal detail /srv/app/services/overview.py")

    monkeypatch.setattr(overview, "build", explode)
    with pytest.raises(RuntimeError):
        client.get(f"/api/projects/{evidence_layers['id']}/overview", headers=auth_headers)
    from fastapi.testclient import TestClient

    quiet = TestClient(client.app, raise_server_exceptions=False)
    response = quiet.get(f"/api/projects/{evidence_layers['id']}/overview", headers=auth_headers)
    assert response.status_code == 500 and response.json() == {"detail": "Internal server error"}


def test_job_starts_are_rate_limited_on_the_new_endpoints(mongo, fake_redis, github, osv, registry):
    from fastapi.testclient import TestClient

    from tests.conftest import register
    from tests.test_intelligence import make_app

    limited = make_app({"JOB_RATE_LIMIT": "3"}, mongo, fake_redis, github, osv, registry)
    with TestClient(limited) as client:
        headers = {"Authorization": f"Bearer {register(client).json()['access_token']}"}
        codes = [client.post(f"/api/projects/{OBJECT_ID}{path}", headers=headers).status_code
                 for path in ("/attack-paths/analyze", "/maintainers/analyze", "/commits/analyze", "/ai-analysis", "/datasets/validate", "/trust/analyze")]
    assert codes[:3] == [404, 404, 404] and codes[3:] == [429, 429, 429]


# --- outbound requests ------------------------------------------------------------------

@pytest.mark.parametrize("env", [
    {"GITHUB_API_URL": "https://evil.example"}, {"GITHUB_API_URL": "https://api.github.com.evil.example"},
    {"GITHUB_API_URL": "https://169.254.169.254"}, {"GITHUB_API_URL": "https://localhost"}, {"GITHUB_API_URL": "https://10.0.0.5"},
    {"GITHUB_API_URL": "https://user:pass@api.github.com"}, {"GITHUB_API_URL": "https://api.github.com:8443"},
    {"GITHUB_API_URL": "https://api.github.com/?x=1"}, {"GITHUB_API_URL": "http://api.github.com"}, {"GITHUB_API_URL": "file:///etc/passwd"},
    {"GITHUB_API_URL": "https://api.github.com\\@evil.example"},
    {"OSV_API_URL": "https://127.0.0.1"}, {"PYPI_API_URL": "https://192.168.1.1"}, {"NPM_REGISTRY_URL": "https://[::1]"}])
def test_outbound_hosts_must_be_allow_listed(env):
    with pytest.raises(SettingsError):
        load_settings({**TEST_ENV, **env})


@pytest.mark.parametrize("host", ["127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.10", "[::1]", "[fd00::1]", "8.8.8.8", "2130706433",
                                  "0x7f000001", "localhost", "mongodb", "redis", "metadata.google.internal", "db.local", "api.corp",
                                  "service.namespace.svc", "backend.cluster.local"])
@pytest.mark.parametrize("pair", [("GITHUB_API_URL", "GITHUB_ALLOWED_HOSTS"), ("OSV_API_URL", "VULNERABILITY_ALLOWED_HOSTS"),
                                  ("PYPI_API_URL", "PACKAGE_METADATA_ALLOWED_HOSTS"), ("NPM_REGISTRY_URL", "PACKAGE_METADATA_ALLOWED_HOSTS")])
def test_an_address_or_internal_name_is_refused_even_when_an_operator_allow_lists_it(host, pair):
    """The allow-list cannot be used to point a collector at the deployment's own network."""
    url_setting, list_setting = pair
    allowed = ",".join(["api.github.com", "api.osv.dev", "pypi.org", "registry.npmjs.org", host.strip("[]")])
    with pytest.raises(SettingsError, match="internal name|not in|not a valid URL"):
        load_settings({**TEST_ENV, url_setting: f"https://{host}", list_setting: allowed})


def test_public_host_names_are_still_accepted():
    loaded = load_settings({**TEST_ENV, "GITHUB_API_URL": "https://github.example.com/api/v3", "GITHUB_ALLOWED_HOSTS": "github.example.com"})
    assert loaded.github_api_url == "https://github.example.com/api/v3"


def test_the_committed_lockfile_matches_the_manifest_and_resolves_from_the_npm_registry_with_integrity_hashes():
    manifest = json.loads((ROOT / "frontend" / "package.json").read_text(encoding="utf-8"))
    lock = json.loads((ROOT / "frontend" / "package-lock.json").read_text(encoding="utf-8"))
    root = lock["packages"][""]
    assert root.get("dependencies") == manifest.get("dependencies") and root.get("devDependencies") == manifest.get("devDependencies")
    packages = {name: entry for name, entry in lock["packages"].items() if name and not entry.get("link")}
    assert len(packages) > 50
    for name, entry in packages.items():
        assert entry["resolved"].startswith("https://registry.npmjs.org/"), name
        assert entry["integrity"].startswith("sha512-"), name


def test_a_github_enterprise_host_must_be_named_explicitly():
    assert load_settings({**TEST_ENV, "GITHUB_API_URL": "https://ghe.example.org/api/v3", "GITHUB_ALLOWED_HOSTS": "ghe.example.org"}).github_api_url \
        == "https://ghe.example.org/api/v3"
    with pytest.raises(SettingsError):
        load_settings({**TEST_ENV, "GITHUB_API_URL": "https://ghe.example.org/api/v3"})


def test_the_github_client_does_not_follow_redirects(client, app, auth_headers, github, repo):
    made = client.post("/api/projects", json={"name": "Redirected", "repository_url": "https://github.com/octo/redirected"}, headers=auth_headers).json()
    github.fail_paths["/commits"] = (302, {"location": "http://169.254.169.254/latest/meta-data/"})
    from tests.test_intelligence import start

    job = start(client, app, auth_headers, made, "/commits/analyze")
    assert job["state"] == "partial" and "MOVED" in job["error"]["message"]
    assert all(request.url.host == "api.github.com" for request in github.requests)


def test_every_outbound_request_of_a_full_run_goes_to_an_allow_listed_host(github, osv, registry, evidence_layers):
    assert {request.url.host for request in github.requests} == {"api.github.com"}
    assert {request.url.host for request in osv.requests} == {"api.osv.dev"}
    assert {request.url.host for request in registry.requests} <= {"pypi.org", "registry.npmjs.org"}
    assert all(request.url.scheme == "https" for request in [*github.requests, *osv.requests, *registry.requests])


def test_repository_content_is_never_executed_or_imported():
    """No analysis module may call anything that runs code or a process."""
    forbidden = re.compile(r"\b(subprocess|os\.system|os\.popen|pty\.|importlib\.import_module|__import__|exec\(|eval\(|pickle\.loads?|"
                           r"marshal\.loads?|compile\(|shell=True)")
    offenders = []
    for path in (ROOT / "backend" / "app").rglob("*.py"):
        if path.parts[-2] == "evaluation" or path.name == "security_changes.py" or path.name == "provider.py":
            continue                       # the rules file holds these words as patterns to look for, never as calls
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            code = line.split("#", 1)[0]
            code = re.sub(r"\"[^\"]*\"|'[^']*'", '""', code)      # a name compared as a string is not a call
            if forbidden.search(code) and "re.compile" not in code:
                offenders.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()[:80]}")
    assert offenders == []


# --- what the repository ships ----------------------------------------------------------

SECRET_PATTERNS = re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
                             r"xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9A-Za-z]{20,}")


def tracked_files():
    try:
        listed = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True, timeout=30).stdout.decode().split("\0")
    except (OSError, subprocess.SubprocessError):
        pytest.skip("not a git checkout")
    return [ROOT / name for name in listed if name]


def test_no_credential_is_tracked_by_git():
    """Every tracked file is scanned for values in the format of a credential.

    Test files contain synthetic values that are assembled from two string
    literals, so that no credential-shaped string exists in the source; a
    literal one anywhere fails this test.
    """
    found = []
    for path in tracked_files():
        if not path.is_file() or path.stat().st_size > 5_000_000:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if SECRET_PATTERNS.search(text):
            found.append(str(path.relative_to(ROOT)))
    assert found == []


def test_env_files_are_ignored_and_examples_hold_placeholders_only():
    ignore = (ROOT / ".gitignore").read_text()
    assert re.search(r"^\.env$", ignore, re.M) and re.search(r"^backend/\.env$", ignore, re.M) and re.search(r"^frontend/\.env$", ignore, re.M)
    names = [path.relative_to(ROOT).as_posix() for path in tracked_files()]
    assert not [name for name in names if re.search(r"(^|/)\.env($|\.local$)", name)]
    for example in (".env.example", "backend/.env.example"):
        assert example in names
        values = dict(line.split("=", 1) for line in (ROOT / example).read_text().splitlines() if "=" in line and not line.lstrip().startswith("#"))
        assert values["GITHUB_TOKEN"] == "your_github_token_here" and values["JWT_SECRET"] == ""
        for key, value in values.items():
            if re.search(r"TOKEN|SECRET|PASSWORD|API_KEY", key):
                assert value in ("", "your_github_token_here"), f"{example}: {key} must be a placeholder"


def test_the_placeholder_token_is_never_sent_to_github():
    for value in ("your_github_token_here", "YOUR_GITHUB_TOKEN_HERE", "changeme", "", "   "):
        assert load_settings({**TEST_ENV, "GITHUB_TOKEN": value}).github_token is None
    assert load_settings({**TEST_ENV, "GITHUB_TOKEN": "a-real-looking-value"}).github_token == "a-real-looking-value"
    assert "a-real-looking-value" not in repr(load_settings({**TEST_ENV, "GITHUB_TOKEN": "a-real-looking-value"}))


def test_the_frontend_holds_no_credentials_and_talks_only_to_its_own_api():
    source = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "frontend" / "src").rglob("*.ts*"))
    assert not SECRET_PATTERNS.search(source)
    assert not re.search(r"GITHUB_TOKEN|JWT_SECRET|MONGO_ROOT_PASSWORD", source)
    assert not re.search(r"https?://(?!localhost|127\.0\.0\.1|github\.com|osv\.dev|www\.w3\.org|reactflow\.dev)[a-z0-9.-]+\.[a-z]{2,}", source), "unexpected external URL"


def test_containers_run_unprivileged_and_expose_nothing_beyond_loopback():
    compose = (ROOT / "docker-compose.yml").read_text()
    assert "no-new-privileges:true" in compose and compose.count("cap_drop: [ALL]") == 2 and compose.count("read_only: true") == 2
    ports = re.findall(r'^\s+- "([^"]+)"$', compose, re.M)
    assert ports and all(port.startswith("127.0.0.1:") for port in ports)
    assert "27017:" not in compose and "6379:" not in compose                 # the database and the queue are not published at all
    backend = (ROOT / "backend" / "Dockerfile").read_text()
    assert "USER 10001" in backend and "useradd --system" in backend
    frontend = (ROOT / "frontend" / "Dockerfile").read_text()
    assert "nginx-unprivileged" in frontend and "npm ci" in frontend
    assert (ROOT / "frontend" / "package-lock.json").is_file()


def test_no_secret_like_value_from_a_commit_is_stored_or_returned_anywhere(client, app, auth_headers, evidence_layers, db):
    run_layers(client, app, auth_headers, evidence_layers, only=("ai", "trust"))
    for name in db.list_collection_names():
        for document in db[name].find({}):
            assert FAKE_TOKEN not in str(document), name
    base = f"/api/projects/{evidence_layers['id']}"
    for path in ("/commits", "/security-events", "/behaviour-events", "/ai-analysis", "/overview", "/report", "/report?format=markdown", "/maintainers"):
        assert FAKE_TOKEN not in client.get(base + path, headers=auth_headers).text, path


def test_actions_that_change_or_export_are_audited(client, app, auth_headers, evidence_layers, db):
    run_layers(client, app, auth_headers, evidence_layers, only=("ai", "trust"))
    client.get(f"/api/projects/{evidence_layers['id']}/report", headers=auth_headers)
    client.post(f"/api/projects/{evidence_layers['id']}/commits/monitoring", headers=auth_headers, json={"enabled": True})
    actions = {entry["action"] for entry in db["audit_logs"].find({})}
    for job_type in ("attack_path_analysis", "maintainer_analysis", "commit_behaviour_analysis", "ai_security_analysis", "dataset_validation",
                     "trust_analysis"):
        assert {f"job.{job_type}.request", f"job.{job_type}.finish"} <= actions, job_type
    assert {"ai.reasoning.complete", "report.generate", "commits.monitoring.set"} <= actions
    assert FAKE_TOKEN not in str(list(db["audit_logs"].find({})))

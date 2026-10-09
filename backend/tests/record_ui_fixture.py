"""Record real API responses for the frontend's browser tests.

    cd backend && python -m tests.record_ui_fixture ../frontend/tests/fixtures/intelligence.json
    cd backend && python -m tests.record_ui_fixture --platform ../frontend/tests/fixtures/platform.json

Runs the same in-memory scenario as tests/test_intelligence.py (stand-ins for
GitHub, OSV and the registries; nothing contacts the network) and writes what
the dependency-intelligence endpoints return, so the browser tests exercise
the page against the API's actual output instead of a hand-written imitation.
"""

from __future__ import annotations

import json
import sys

import httpx
import mongomock
from fastapi.testclient import TestClient

from app.config.settings import load_settings
from app.main import create_app
from tests.conftest import TEST_ENV, FakeRedis, FakeRepository, GitHubStub, OsvStub, RegistryStub, register
from tests.test_intelligence import REPO, REPO_URL, get, load_advisories, load_packages, start, url


def record() -> dict:
    github, osv, registry = GitHubStub(), OsvStub(), RegistryStub()
    github.repo = FakeRepository(REPO)
    load_advisories(osv)
    load_packages(registry)
    app = create_app(load_settings(TEST_ENV), mongo_client=mongomock.MongoClient(tz_aware=True), redis_client=FakeRedis(),
                     github_transport=httpx.MockTransport(github.handler), provider_transport=httpx.MockTransport(osv.handler),
                     registry_transport=httpx.MockTransport(registry.handler))
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {register(client).json()['access_token']}"}
        project = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=headers).json()
        start(client, app, headers, project, "/analysis/dependencies")

        def details(path: str, listing: dict, limit: int | None = None) -> dict:
            return {item["dependency_id"]: get(client, headers, project, f"{path}/{item['dependency_id']}") for item in listing["items"][:limit]}

        # 1. Fragility only: no vulnerability check exists yet.
        fragility_job = start(client, app, headers, project, "/fragility/analyze")
        fragility_list = get(client, headers, project, "/fragility")
        fragility = {"job": fragility_job, "list": fragility_list, "details": details("/fragility", fragility_list, 2)}

        # 2. Full analysis after a vulnerability check, before any reachability analysis.
        start(client, app, headers, project, "/vulnerabilities/sync")
        start(client, app, headers, project, "/predictive-risk/analyze")
        earlier = get(client, headers, project, "/predictive-risk")

        # 3. Full analysis again once code reachability is known. This is the state the page normally shows.
        start(client, app, headers, project, "/code-reachability/analyze")
        job = start(client, app, headers, project, "/predictive-risk/analyze")
        listing = get(client, headers, project, "/predictive-risk")
        history = get(client, headers, project, "/predictive-risk/history", kind="predictive")
        predictive = {
            "job": job, "list": listing, "details": details("/predictive-risk", listing),
            "graph": get(client, headers, project, "/predictive-risk/graph"), "history": history,
            "compare": get(client, headers, project, "/predictive-risk/compare", base=earlier["analysis"]["id"], target=listing["analysis"]["id"]),
        }
        assert client.get(url(project, "/predictive-risk"), headers=headers).status_code == 200
    return {"project_id": project["id"], "fragility": fragility, "predictive": predictive}


def record_platform() -> dict:
    """Responses of the attack-path, maintainer, commit, reasoning, dataset, trust, overview and report endpoints.

    Recorded twice: for a project with only a dependency inventory ("empty": what the pages show before their analysis
    has run) and for the same project after every layer has been analysed ("full").
    """
    from tests.pipeline import build_repository, run_layers

    github, osv, registry = GitHubStub(), OsvStub(), RegistryStub()
    build_repository(github)
    load_advisories(osv)
    load_packages(registry)
    app = create_app(load_settings(TEST_ENV), mongo_client=mongomock.MongoClient(tz_aware=True), redis_client=FakeRedis(),
                     github_transport=httpx.MockTransport(github.handler), provider_transport=httpx.MockTransport(osv.handler),
                     registry_transport=httpx.MockTransport(registry.handler))
    app.state.github.sleep = lambda _seconds: None
    with TestClient(app) as client:
        headers = {"Authorization": f"Bearer {register(client).json()['access_token']}"}
        project = client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=headers).json()
        run_layers(client, app, headers, project, only=("dependencies",))

        def lists() -> dict:
            return {name: get(client, headers, project, path) for name, path in (
                ("attack_paths", "/attack-paths"), ("maintainers", "/maintainers"), ("commits", "/commits"),
                ("security_events", "/security-events"), ("ai", "/ai-analysis"), ("datasets", "/datasets"), ("trust", "/trust"),
                ("trust_history", "/trust/history"), ("overview", "/overview"), ("report", "/report"))}

        empty = lists()
        # An early trust analysis, so that the history holds an INSUFFICIENT_DATA result followed by a scored one.
        run_layers(client, app, headers, project, only=("vulnerabilities", "trust"))
        insufficient = get(client, headers, project, "/trust")
        insufficient_explanation = get(client, headers, project, "/trust/explanation")
        jobs = run_layers(client, app, headers, project, skip=("dependencies", "vulnerabilities"))
        full = lists()
        paths = full["attack_paths"]["items"]
        full["attack_path_details"] = {item["attack_path_id"]: get(client, headers, project, f"/attack-paths/{item['attack_path_id']}") for item in paths}
        full["attack_graph"] = get(client, headers, project, "/attack-paths/graph")
        full["attack_what_if"] = get(client, headers, project, "/attack-paths/graph", without="npm:qs@6.7.0")
        people = full["maintainers"]["items"]
        full["maintainer_details"] = {item["maintainer_id"]: get(client, headers, project, f"/maintainers/{item['maintainer_id']}") for item in people}
        full["commit_details"] = {item["commit_sha"]: get(client, headers, project, f"/commits/{item['commit_sha']}")
                                  for item in full["commits"]["items"] if item["indicator_types"]}
        first = full["commits"]["items"][0]
        full["commit_details"][first["commit_sha"]] = get(client, headers, project, f"/commits/{first['commit_sha']}")
        full["finding_details"] = {item["finding_id"]: get(client, headers, project, f"/ai-analysis/{item['finding_id']}") for item in full["ai"]["items"]}
        dataset_id = full["datasets"]["current"]["id"]
        full["dataset"] = get(client, headers, project, f"/datasets/{dataset_id}")
        full["dataset_quality"] = get(client, headers, project, f"/datasets/{dataset_id}/quality")
        full["trust_explanation"] = get(client, headers, project, "/trust/explanation")
        scores = full["trust_history"]["items"]
        full["trust_compare"] = get(client, headers, project, "/trust/compare", base=scores[-1]["id"], target=scores[0]["id"])
        full["report_markdown"] = client.get(url(project, "/report"), headers=headers, params={"format": "markdown"}).text
        full["jobs"] = jobs
        dashboard = client.get("/api/dashboard/summary", headers=headers).json()
        evaluation = client.get("/api/dashboard/evaluation", headers=headers).json()
    return {"project_id": project["id"], "empty": empty, "insufficient": {"trust": insufficient, "explanation": insufficient_explanation},
            "full": full, "dashboard": dashboard, "evaluation": evaluation}


if __name__ == "__main__":
    platform = "--platform" in sys.argv
    target = [argument for argument in sys.argv[1:] if not argument.startswith("--")][0]
    with open(target, "w", encoding="utf-8") as handle:
        json.dump(record_platform() if platform else record(), handle, sort_keys=True, separators=(",", ":"))     # compact: a recording, not a file to edit
        handle.write("\n")
    print(f"wrote {target}")

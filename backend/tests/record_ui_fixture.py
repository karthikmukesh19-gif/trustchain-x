"""Record real API responses for the frontend's browser tests.

    cd backend && python -m tests.record_ui_fixture ../frontend/tests/fixtures/intelligence.json

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


if __name__ == "__main__":
    target = sys.argv[1]
    with open(target, "w", encoding="utf-8") as handle:
        json.dump(record(), handle, sort_keys=True, separators=(",", ":"))     # compact: this is a recording, not a file to edit
        handle.write("\n")
    print(f"wrote {target}")

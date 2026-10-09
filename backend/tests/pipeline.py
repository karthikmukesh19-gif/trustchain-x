"""A project taken through every analysis layer, for tests that need the layers together.

The repository is the dependency-intelligence fixture (tests/test_intelligence.py)
with an invented commit history, contributors and releases added. GHSA-*
advisories are real public records; TEST-* advisories, registry contents and
the history are test data.
"""

from __future__ import annotations

import pytest

from tests.conftest import FakeRepository
from tests.history import ago, changed, raw_commit, release
from tests.test_intelligence import REPO, REPO_URL, load_advisories, load_packages, start

# Synthetic value in the format of a GitHub token. It was generated for the tests and grants access to nothing.
FAKE_TOKEN = "ghp_" + "Zx9cVb8nMa7sDf6gHj5kLq4wEr3tYu2iOp1A"

STEPS = (
    ("dependencies", "/analysis/dependencies"), ("vulnerabilities", "/vulnerabilities/sync"), ("sbom", "/sbom/generate"),
    ("reachability", "/code-reachability/analyze"), ("predictive", "/predictive-risk/analyze"), ("attack_paths", "/attack-paths/analyze"),
    ("commits", "/commits/analyze"), ("maintainers", "/maintainers/analyze"), ("dataset", "/datasets/validate"), ("ai", "/ai-analysis"),
    ("trust", "/trust/analyze"),
)


def project_history() -> list[dict]:
    """Forty commits over about four months, newest first: mostly routine work by one person, a second contributor, and a few notable changes."""
    commits = [raw_commit(n, ago(days=3 * n + 1, hours=n % 6), "alice" if n % 9 else "bob", message=f"Routine change {n}",
                          files=[changed(f"app/module{n % 5}.py", [f"value = {n}"] * (6 + n % 4), ["value = 0"])]) for n in range(40)]
    commits[12] = raw_commit(12, ago(days=37), "alice", message="Bump requests",
                             files=[changed("requirements.txt", ["requests==2.19.1"], ["requests==2.18.0"])])
    commits[5] = raw_commit(5, ago(days=16), "alice", message="Automate release",
                            files=[changed(".github/workflows/release.yml", ["run: python scripts/release.py"]),
                                   changed("scripts/release.py", ["subprocess.run(command, shell=True)", f'PUBLISH_TOKEN = "{FAKE_TOKEN}"'])])
    commits[2] = raw_commit(2, ago(days=7), "alice", message="Update web dependencies",
                            files=[changed("web/package.json", ['"express": "4.17.1"'], ['"express": "4.16.0"']),
                                   changed("web/package-lock.json", ['"version": "4.17.1"'], ['"version": "4.16.0"'])])
    return commits


def build_repository(github) -> FakeRepository:
    github.repo = FakeRepository(REPO)
    github.repo.history = project_history()
    github.repo.people = [{"login": "alice", "contributions": 35, "type": "User"}, {"login": "bob", "contributions": 5, "type": "User"}]
    github.repo.published = [release(f"v1.{4 - n}.0", ago(days=10 + 30 * n), "alice") for n in range(5)]
    return github.repo


def run_layers(client, app, headers, project, *, only: tuple[str, ...] | None = None, skip: tuple[str, ...] = (), verify_sbom: bool = True) -> dict[str, dict]:
    """Run the analysis steps in order and return each job. Steps listed in `skip` (or not in `only`) are left out."""
    jobs: dict[str, dict] = {}
    for name, path in STEPS:
        if name in skip or (only is not None and name not in only):
            continue
        jobs[name] = start(client, app, headers, project, path)
        assert jobs[name]["state"] in ("completed", "partial"), (name, jobs[name])
        if name == "sbom" and verify_sbom:
            sbom_id = client.get(f"/api/projects/{project['id']}/sbom", headers=headers).json()["latest"]["id"]
            assert client.post(f"/api/projects/{project['id']}/sbom/{sbom_id}/verify", headers=headers).status_code == 200
    return jobs


@pytest.fixture
def repo(github):
    return build_repository(github)


@pytest.fixture
def advisories(osv):
    return load_advisories(osv)


@pytest.fixture
def packages(registry):
    return load_packages(registry)


@pytest.fixture
def created(client, auth_headers, repo, advisories, packages):
    return client.post("/api/projects", json={"name": "Demo", "repository_url": REPO_URL}, headers=auth_headers).json()


@pytest.fixture
def evidence_layers(client, app, auth_headers, created):
    """A project with every evidence layer analysed (everything except cross-layer reasoning and trust)."""
    run_layers(client, app, auth_headers, created, skip=("ai", "trust"))
    return created

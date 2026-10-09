"""Run every analysis layer, end to end, on a real repository read from a local git clone.

    python -m tests.real_repository_run --clone /path/to/clone --owner OWNER --name REPO
           [--advisories /path/to/advisory-database/advisories/github-reviewed] [--out result.json]

For environments that cannot reach api.github.com, api.osv.dev or the package
registries. The platform itself is unchanged and runs in-process (API, job
system and worker; MongoDB replaced by mongomock). What it normally fetches is
served by local stand-ins built from real data:

  GitHub      the clone's files (as git blobs), its commits and their diffs, in the shapes of the GitHub REST API.
              Like GitHub, a commit lists at most 300 files and carries no patch for a very large diff.
              A clone does not contain GitHub logins, contributor statistics, releases or repository statistics;
              those endpoints answer 503, and the platform reports what depends on them as unknown.
  OSV         with --advisories: the reviewed records of github.com/github/advisory-database (OSV format).
              A query for a package returns every record that names it; the platform's own matcher decides
              which versions are affected. Without --advisories every request fails and the layer is unavailable.
  registries  always unreachable. Version and release-age facts are reported as unknown.

Nothing from the repository is executed: git plumbing commands read objects from the clone.
The output states, for every layer, what was produced and what was not. It is a record of one run, not a benchmark.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import mongomock
from fastapi.testclient import TestClient

from app.config.settings import load_settings
from app.main import create_app
from tests import mongomock_compat  # noqa: F401  (adapts mongomock to the driver calls the application makes)
from tests.conftest import TEST_ENV, FakeRedis, FakeRepository, GitHubStub, OsvStub, RegistryStub, respond_list, run_worker

STEPS = (
    ("dependencies", "/analysis/dependencies"), ("vulnerabilities", "/vulnerabilities/sync"), ("sbom", "/sbom/generate"),
    ("reachability", "/code-reachability/analyze"), ("predictive", "/predictive-risk/analyze"), ("attack_paths", "/attack-paths/analyze"),
    ("commits", "/commits/analyze"), ("maintainers", "/maintainers/analyze"), ("dataset", "/datasets/validate"), ("ai", "/ai-analysis"),
    ("trust", "/trust/analyze"),
)
_SEP, _END = "\x1f", "\x1e"
# GitHub's commit endpoint lists at most 300 files and leaves the patch out for large diffs. The stand-in does the same, so a
# commit that adds a vendored directory is served the way the platform would receive it. The size bound is an approximation.
MAX_FILES_SERVED, MAX_PATCH_SERVED = 300, 100_000


def git(clone: Path, *arguments: str) -> bytes:
    """Read from the clone. Only plumbing that inspects objects; nothing is checked out and no hook or repository code runs."""
    return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(clone), *arguments], capture_output=True, check=True,
                          timeout=300).stdout


def read_files(clone: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for entry in git(clone, "ls-tree", "-r", "-z", "HEAD").split(b"\0"):
        if not entry:
            continue
        meta, path = entry.split(b"\t", 1)
        mode, kind, blob = meta.decode().split()
        if kind == "blob" and mode in ("100644", "100755"):                  # regular files only: no symlinks, no submodules
            files[path.decode("utf-8", "replace")] = git(clone, "cat-file", "blob", blob)
    return files


def changed_files(clone: Path, sha: str) -> list[dict[str, Any]]:
    """The files a commit changed, with unified-diff patches, in the shape of GitHub's single-commit response."""
    text = git(clone, "show", "--format=", "--no-color", "--no-ext-diff", "--patch", "-M", "--root", sha).decode("utf-8", "replace")
    files = []
    for block in re.split(r"(?m)^diff --git ", text)[1:]:
        header, _, body = block.partition("\n@@")
        patch = ("@@" + body).rstrip("\n") if body else None
        name = re.search(r"(?m)^\+\+\+ b/(.+)$", header) or re.search(r"(?m)^rename to (.+)$", header) or re.match(r"a/(.+?) b/", header)
        if "deleted file mode" in header:
            name = re.search(r"(?m)^--- a/(.+)$", header) or name
        if name is None:
            continue
        status = ("added" if "new file mode" in header else "removed" if "deleted file mode" in header
                  else "renamed" if "rename from" in header else "modified")
        lines = patch.split("\n") if patch else []
        added = sum(1 for line in lines if line.startswith("+") and not line.startswith("+++"))
        removed = sum(1 for line in lines if line.startswith("-") and not line.startswith("---"))
        entry = {"filename": name.group(1).strip(), "status": status, "additions": added, "deletions": removed, "changes": added + removed}
        if patch is not None and len(patch) <= MAX_PATCH_SERVED:
            entry["patch"] = patch
        files.append(entry)
    return files[:MAX_FILES_SERVED]


def read_history(clone: Path, limit: int) -> list[dict[str, Any]]:
    """Commits newest first, as GitHub commit objects. `author` is null: a clone records names and addresses, not GitHub logins."""
    fields = ("%H", "%P", "%T", "%an", "%ae", "%aI", "%cn", "%ce", "%cI", "%B")
    raw = git(clone, "log", f"-{limit}", f"--format={_SEP.join(fields)}{_END}").decode("utf-8", "replace")
    commits = []
    for record in raw.split(_END):
        if not record.strip():
            continue
        sha, parents, tree, a_name, a_mail, a_date, c_name, c_mail, c_date, message = record.strip("\n").split(_SEP)
        files = changed_files(clone, sha)
        utc = lambda value: datetime.fromisoformat(value).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
        commits.append({
            "sha": sha,
            "commit": {"author": {"name": a_name, "email": a_mail, "date": utc(a_date)},
                       "committer": {"name": c_name, "email": c_mail, "date": utc(c_date)},
                       "message": message.strip(), "tree": {"sha": tree}, "verification": {"verified": False}},
            "author": None, "committer": None, "parents": [{"sha": parent} for parent in parents.split()],
            "stats": {"additions": sum(f["additions"] for f in files), "deletions": sum(f["deletions"] for f in files)},
            "files": files,
        })
    return commits


class ClonedRepository(FakeRepository):
    """A real repository's content and history behind the GitHub endpoints the platform calls."""

    def __init__(self, clone: Path, commits: int) -> None:
        branch = git(clone, "rev-parse", "--abbrev-ref", "HEAD").decode().strip()
        super().__init__(read_files(clone), branch=branch)
        self.history = read_history(clone, commits)
        self.head = self.history[0]

    @property
    def commit_sha(self) -> str:
        return self.head["sha"]

    @property
    def tree_sha(self) -> str:
        return self.head["commit"]["tree"]["sha"]

    def respond(self, path: str) -> httpx.Response | None:
        rest = path.strip("/").split("/")[3:]
        if not rest:
            # Only what a clone establishes. Stars, forks, licence, language and dates are not in a clone and are left unknown.
            return httpx.Response(200, json={"default_branch": self.branch, "visibility": "public",
                                             "size": sum(len(content) for content in self.files.values()) // 1024})
        if rest[0] in ("contributors", "releases"):
            return httpx.Response(503, json={"message": "not available from a clone"})
        if rest[0] == "commits" and len(rest) == 2 and rest[1] in (self.branch, "HEAD"):
            return httpx.Response(200, json=self.head)
        return super().respond(path)


def normalise(ecosystem: str, name: str) -> tuple[str, str]:
    return ecosystem.lower(), re.sub(r"[-_.]+", "-", name).lower() if ecosystem.lower() == "pypi" else name.lower()


class AdvisoryDirectory(OsvStub):
    """Real OSV-format records from a local directory. A package query returns every record that names the package."""

    def __init__(self, directory: Path, wanted: set[tuple[str, str]]) -> None:
        super().__init__()
        self.by_package: dict[tuple[str, str], list[str]] = {}
        for file in directory.rglob("*.json"):
            text = file.read_text(encoding="utf-8")
            if not any(f'"{name}"' in text.lower() for _eco, name in wanted):       # cheap pre-filter before parsing
                continue
            record = json.loads(text)
            if record.get("withdrawn"):
                continue
            keys = {normalise(a["package"]["ecosystem"], a["package"]["name"]) for a in record.get("affected") or [] if a.get("package")}
            if keys & wanted:
                self.add(record)
                for key in keys & wanted:
                    self.by_package.setdefault(key, []).append(record["id"])

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.method == "POST" and request.url.path.endswith("/v1/querybatch"):
            self.requests.append(request)
            results = []
            for query in json.loads(request.content)["queries"]:
                ids = sorted(self.by_package.get(normalise(query["package"]["ecosystem"], query["package"]["name"]), []))
                results.append({"vulns": [{"id": i, "modified": self.records[i].get("modified", "")} for i in ids]} if ids else {})
            return httpx.Response(200, json={"results": results})
        return super().handler(request)


def run(clone: Path, owner: str, name: str, advisories: Path | None, commits: int) -> dict[str, Any]:
    settings = load_settings({**TEST_ENV, "COMMIT_ANALYSIS_MAX_COMMITS": str(min(commits, 200)), "MAINTAINER_MAX_COMMITS": str(commits)})
    github, registry = GitHubStub(), RegistryStub()
    github.repo = ClonedRepository(clone, commits)
    registry.error = httpx.ConnectError("registry unreachable in this run")
    osv: OsvStub = OsvStub()
    if advisories is None:
        osv.error = httpx.ConnectError("advisory source unreachable in this run")

    def github_handler(request: httpx.Request) -> httpx.Response:
        github.requests.append(request)
        return github.repo.respond(request.url.path) or respond_list(github.repo, request) or httpx.Response(404, json={"message": "Not Found"})

    holder = {"osv": osv}
    app = create_app(settings, mongo_client=mongomock.MongoClient(tz_aware=True), redis_client=FakeRedis(),
                     github_transport=httpx.MockTransport(github_handler),
                     provider_transport=httpx.MockTransport(lambda request: holder["osv"].handler(request)),
                     registry_transport=httpx.MockTransport(registry.handler))
    for client in (*app.state.registries.values(), app.state.github, *app.state.providers.values()):
        client.sleep = lambda _seconds: None

    result: dict[str, Any] = {"repository": f"{owner}/{name}", "commit": github.repo.commit_sha, "files": len(github.repo.files),
                              "commits_available": len(github.repo.history), "started_at": datetime.now(timezone.utc).isoformat(),
                              "steps": {}}
    with TestClient(app) as client:
        token = client.post("/api/auth/register", json={"email": "run@example.com", "password": "local-run-passw0rd", "full_name": "Local run"}).json()
        headers = {"Authorization": f"Bearer {token['access_token']}"}
        project = client.post("/api/projects", json={"name": name, "repository_url": f"https://github.com/{owner}/{name}"}, headers=headers).json()
        base = f"/api/projects/{project['id']}"
        for step, path in STEPS:
            if step == "vulnerabilities" and advisories is not None:
                listed = client.get(f"{base}/dependencies?limit=1", headers=headers).json()
                wanted, skip = set(), 0
                while skip < listed["total"]:
                    page = client.get(f"{base}/dependencies?limit=200&skip={skip}", headers=headers).json()["items"]
                    wanted |= {normalise("pypi" if d["ecosystem"] == "pypi" else d["ecosystem"], d["name"]) for d in page}
                    skip += 200
                holder["osv"] = AdvisoryDirectory(advisories, wanted)
                result["advisory_records_loaded"] = len(holder["osv"].records)
            began = time.monotonic()
            response = client.post(base + path, headers=headers)
            if response.status_code != 202:
                result["steps"][step] = {"state": "not_started", "http_status": response.status_code, "detail": response.json().get("detail")}
                continue
            run_worker(app)
            job = client.get(f"{base}/jobs", headers=headers).json()["items"][0]
            result["steps"][step] = {"state": job["state"], "message": job.get("message"), "seconds": round(time.monotonic() - began, 2),
                                     **({"error": job["error"]} if job.get("error") else {}),
                                     **({"partial": job["partial"]} if job.get("partial") else {})}
            if step == "sbom" and job["state"] in ("completed", "partial"):
                latest = client.get(f"{base}/sbom", headers=headers).json()["latest"]
                verified = client.post(f"{base}/sbom/{latest['id']}/verify", headers=headers)
                checks = verified.json().get("checks") or [] if verified.status_code == 200 else []
                result["steps"]["sbom_verification"] = {"http_status": verified.status_code, "checks": len(checks),
                                                        "failed_checks": sorted(c["name"] for c in checks if not c["ok"])}
        overview = client.get(f"{base}/overview", headers=headers).json()
        trust = client.get(f"{base}/trust", headers=headers).json()
        report = client.get(f"{base}/report", headers=headers)
        result["layers"] = {layer["name"]: layer["status"] for layer in overview["layers"]}
        result["not_available"] = overview["missing"]
        current = trust.get("trust") or {}
        result["trust"] = {key: current.get(key) for key in ("status", "trust_score", "risk_score", "band", "confidence", "coverage", "risk_low",
                                                              "risk_high", "unknown_components")}
        result["report"] = {"http_status": report.status_code}
        if report.status_code == 200:
            body = report.json()
            result["report"].update({"sections": len(body.get("sections") or []), "statements": body.get("statement_count"),
                                     "evidence_items": len(body.get("evidence") or []),
                                     "unsupported_statements": len(body.get("unsupported_statements") or [])})
        result["executive"] = overview["executive"]
        result["measured"] = overview["research"].get("measured")
    hosts: dict[str, int] = {}
    for request in (*github.requests, *holder["osv"].requests, *osv.requests, *registry.requests):
        hosts[request.url.host] = hosts.get(request.url.host, 0) + 1
    result["requests_by_host"] = hosts
    result["finished_at"] = datetime.now(timezone.utc).isoformat()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--clone", type=Path, required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--advisories", type=Path)
    parser.add_argument("--commits", type=int, default=200)
    parser.add_argument("--out", type=Path)
    arguments = parser.parse_args(argv)
    result = run(arguments.clone, arguments.owner, arguments.name, arguments.advisories, arguments.commits)
    text = json.dumps(result, indent=2, default=str)
    if arguments.out:
        arguments.out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())

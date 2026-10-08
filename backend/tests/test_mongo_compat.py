"""Regression tests for the PyMongo / mongomock bulk-write incompatibility.

PyMongo >= 4.11 passes ``sort=`` to the bulk builder for every UpdateOne /
ReplaceOne. mongomock <= 4.3.0 rejected that argument, which made
``_record_versions`` raise TypeError and every analysis job end as ``failed``.
"""

import inspect
from datetime import datetime, timedelta, timezone

import pytest
from mongomock.collection import BulkOperationBuilder
from pymongo import ReplaceOne, UpdateOne

from app.services.analysis import _record_versions


def node(name, version, ecosystem="pypi"):
    purl = f"pkg:{ecosystem}/{name}@{version}" if version else f"pkg:{ecosystem}/{name}"
    return {"ecosystem": ecosystem, "normalized_name": name, "version": version, "purl": purl}


@pytest.mark.parametrize("method", ["add_update", "add_replace"])
def test_bulk_builder_accepts_every_argument_pymongo_sends(method):
    """If PyMongo's operations take ``sort``, the test database's bulk builder must too."""
    if "sort" in inspect.signature(UpdateOne.__init__).parameters:
        assert "sort" in inspect.signature(getattr(BulkOperationBuilder, method)).parameters


def test_bulk_write_of_upserts_runs_on_the_test_database(db):
    """The exact shape of call that used to raise TypeError."""
    result = db.things.bulk_write(
        [
            UpdateOne({"k": 1}, {"$setOnInsert": {"created": True}, "$set": {"seen": 1}}, upsert=True),
            UpdateOne({"k": 1}, {"$setOnInsert": {"created": False}, "$set": {"seen": 2}}, upsert=True),
            ReplaceOne({"k": 2}, {"k": 2, "replaced": True}, upsert=True),
        ],
        ordered=False,
    )
    assert result.upserted_count == 2
    assert db.things.find_one({"k": 1}, {"_id": 0}) == {"k": 1, "created": True, "seen": 2}
    assert db.things.find_one({"k": 2}, {"_id": 0}) == {"k": 2, "replaced": True}


def test_record_versions_catalogues_resolved_versions_only(db):
    now = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)
    _record_versions(db, [node("flask", "3.0.0"), node("requests", None), node("react", "18.3.1", "npm")], now)

    stored = {(d["ecosystem"], d["package_name"], d["version"]) for d in db.dependency_versions.find({})}
    assert stored == {("pypi", "flask", "3.0.0"), ("npm", "react", "18.3.1")}   # the unresolved one is not catalogued
    flask = db.dependency_versions.find_one({"package_name": "flask"})
    assert flask["purl"] == "pkg:pypi/flask@3.0.0"
    assert flask["source"] == "repository_analysis"
    assert flask["first_seen_at"] == flask["last_seen_at"] == now


def test_record_versions_is_idempotent_and_tracks_last_seen(db):
    first = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)
    later = first + timedelta(days=3)
    _record_versions(db, [node("flask", "3.0.0")], first)
    _record_versions(db, [node("flask", "3.0.0"), node("flask", "3.1.0")], later)

    assert db.dependency_versions.count_documents({}) == 2
    original = db.dependency_versions.find_one({"version": "3.0.0"})
    assert original["first_seen_at"] == first and original["last_seen_at"] == later
    assert db.dependency_versions.find_one({"version": "3.1.0"})["first_seen_at"] == later


def test_record_versions_handles_more_than_one_batch(db):
    now = datetime(2026, 10, 8, tzinfo=timezone.utc)
    _record_versions(db, [node(f"pkg-{i}", "1.0.0") for i in range(2500)], now)
    assert db.dependency_versions.count_documents({}) == 2500


def test_record_versions_with_nothing_resolved_writes_nothing(db):
    _record_versions(db, [node("requests", None)], datetime(2026, 10, 8, tzinfo=timezone.utc))
    _record_versions(db, [], datetime(2026, 10, 8, tzinfo=timezone.utc))
    assert db.dependency_versions.count_documents({}) == 0


def test_an_explicit_sort_is_never_silently_ignored(db):
    """Where the adapter is in use, asking for a sort fails loudly instead of being dropped."""
    if not getattr(BulkOperationBuilder.add_update, "__mongomock_compat__", False):
        pytest.skip("this mongomock implements bulk-update sort itself")
    with pytest.raises(NotImplementedError):
        db.things.bulk_write([UpdateOne({"k": 1}, {"$set": {"v": 1}}, sort={"k": 1})])

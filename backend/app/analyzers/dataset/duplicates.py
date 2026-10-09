"""Duplicate, near-duplicate and contradicting records."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from app.analyzers.dataset.integrity import canonical

MAX_GROUPS = 50


def find(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Exact duplicates, repeated identities, indistinguishable records and conflicting labels.

      exact            the same content stored under more than one record id
      identity         the same ecosystem, name and version more than once
      near             different packages whose features are identical (nothing in the data tells them apart)
      label conflicts  identical features with different labels: the labels cannot both follow from the features
    """
    by_content: dict[bytes, list[str]] = defaultdict(list)
    by_identity: dict[tuple[Any, Any, Any], list[str]] = defaultdict(list)
    by_features: dict[bytes, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        identity = record.get("identity") or {}
        record_id = str(record.get("record_id"))
        by_content[canonical({"identity": identity, "features": record.get("features"), "labels": record.get("labels")})].append(record_id)
        by_identity[(identity.get("ecosystem"), str(identity.get("name") or "").lower(), identity.get("version"))].append(record_id)
        by_features[canonical(record.get("features"))].append(record)

    exact = [ids for ids in by_content.values() if len(ids) > 1]
    repeated = [ids for ids in by_identity.values() if len(ids) > 1]
    near, conflicts = [], []
    for group in by_features.values():
        if len(group) < 2:
            continue
        ids = [str(record.get("record_id")) for record in group]
        near.append(ids)
        if len({canonical(record.get("labels")) for record in group}) > 1:
            conflicts.append(ids)
    duplicate_records = sum(len(ids) - 1 for ids in exact)
    repeated_records = sum(len(ids) - 1 for ids in repeated)
    conflicting = sum(len(ids) for ids in conflicts)
    total = len(records)
    affected = min(total, max(duplicate_records, repeated_records) + conflicting)
    return {
        "records": total, "exact_duplicate_records": duplicate_records, "exact_duplicate_groups": [sorted(ids)[:10] for ids in exact[:MAX_GROUPS]],
        "repeated_identity_records": repeated_records, "repeated_identity_groups": [sorted(ids)[:10] for ids in repeated[:MAX_GROUPS]],
        "near_duplicate_groups": len(near), "near_duplicate_records": sum(len(ids) for ids in near),
        "near_duplicate_examples": [sorted(ids)[:10] for ids in sorted(near, key=lambda ids: (-len(ids), sorted(ids)))[:10]],
        "label_conflict_records": conflicting, "label_conflict_groups": [sorted(ids)[:10] for ids in conflicts[:MAX_GROUPS]],
        "value": round(1 - affected / total, 4) if total else None,
        "note": "Near duplicates are packages the features cannot tell apart. They are reported, not penalised: many small packages are alike.",
    }

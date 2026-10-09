"""Record and dataset hashes (SHA-256) and their verification.

A record's hash covers its identity, features, labels and provenance in a
canonical JSON form. A dataset's hash covers every record id with its record
hash, in sorted order. Each dataset version also carries a chain hash over
the previous version's chain hash, so that an altered or removed earlier
version is detectable from any later one.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

ALGORITHM = "SHA-256"
CANONICAL_FORM = "UTF-8 JSON, object keys sorted, no insignificant whitespace, timestamps as UTC ISO 8601 with milliseconds"
HASHED_FIELDS = ("record_id", "identity", "features", "labels", "provenance")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_encode).encode("utf-8")


def _encode(value: Any) -> str:
    """Timestamps as UTC with millisecond precision (what the database keeps), so a stored record hashes as it did before storing."""
    if isinstance(value, datetime):
        moment = (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
        return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"
    return str(value)


def record_hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(canonical({name: record.get(name) for name in HASHED_FIELDS})).hexdigest()


def dataset_hash(records: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for record_id, value in sorted((str(record["record_id"]), record["record_hash"]) for record in records):
        digest.update(f"{record_id}\x00{value}\n".encode())
    return digest.hexdigest()


def chain_hash(previous_chain_hash: str | None, current_dataset_hash: str) -> str:
    return hashlib.sha256(f"{previous_chain_hash or ''}:{current_dataset_hash}".encode()).hexdigest()


def verify(records: list[dict[str, Any]], expected_dataset_hash: str | None, expected_count: int | None = None) -> dict[str, Any]:
    """Recompute every hash and compare with what is stored.

    Returns {"status": VERIFIED | MISMATCH, ...} with the ids of records whose
    content no longer matches their stored hash, and whether the set of
    records as a whole still matches the dataset hash (which also catches
    added and removed records).
    """
    altered = [str(record.get("record_id")) for record in records if record.get("record_hash") != record_hash(record)]
    recomputed = dataset_hash([{**record, "record_hash": record_hash(record)} for record in records])
    set_matches = expected_dataset_hash is None or recomputed == expected_dataset_hash
    count_matches = expected_count is None or expected_count == len(records)
    ok = not altered and set_matches and count_matches
    return {"status": "VERIFIED" if ok else "MISMATCH", "algorithm": ALGORITHM, "records_checked": len(records),
            "altered_records": altered[:100], "altered_count": len(altered), "dataset_hash_matches": set_matches,
            "record_count_matches": count_matches, "recomputed_dataset_hash": recomputed}

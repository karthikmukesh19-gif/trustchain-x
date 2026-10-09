"""Dataset quality score and validation status (model "dataset-quality-v1").

    quality_score = 100 × Σ(weight × value of evaluated factors) / Σ(weight of evaluated factors)

  integrity      25   every record and the dataset as a whole still match their SHA-256 hashes
  completeness   20   share of feature and label cells that hold a value
  provenance     15   fields traceable to a source, and how many analysis layers contributed
  consistency    15   records free of schema, range and cross-field problems
  uniqueness     10   records that are not duplicates and do not contradict each other
  balance        10   representation of the smaller labelled class
  timestamps      5   source times that are present and in a possible order

Statuses:

  VALID            the checks pass and the score is at least 80
  WARNING          usable, with stated weaknesses
  LOW_CONFIDENCE   too small, too incomplete or too low-scoring to rely on
  INVALID          integrity failed, or records break the schema
  UNKNOWN          there is nothing to validate

No status means that the data is free of manipulation.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from app.analyzers.dataset import balance, duplicates, integrity, provenance, quality

MODEL_VERSION = "dataset-quality-v1"
WEIGHTS = {"integrity": 25, "completeness": 20, "provenance": 15, "consistency": 15, "uniqueness": 10, "balance": 10, "timestamps": 5}
VALID, WARNING, LOW_CONFIDENCE, INVALID, UNKNOWN = "VALID", "WARNING", "LOW_CONFIDENCE", "INVALID", "UNKNOWN"
STATUSES = (VALID, WARNING, LOW_CONFIDENCE, INVALID, UNKNOWN)
MIN_RECORDS = 10                 # fewer records than this are too few to rely on
SUFFICIENT_RECORDS = 30          # at this size, confidence is no longer reduced for being small
LIMITATION = ("These checks detect damage, gaps, duplicates and contradictions. They cannot establish that the data is free of deliberate "
              "manipulation: a well-formed, consistent record can still be wrong at its source.")


def timestamps(records: list[dict[str, Any]], now: datetime, snapshot_committed_at: datetime | None) -> dict[str, Any]:
    """Source timestamps must exist, must not lie in the future, and must not predate the commit they describe."""
    total = missing = future = early = 0
    for record in records:
        for entry in record.get("provenance") or []:
            total += 1
            moment = entry.get("collected_at")
            if not isinstance(moment, datetime):
                missing += 1
                continue
            moment = moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)
            future += moment > now + timedelta(minutes=5)
            early += snapshot_committed_at is not None and moment < snapshot_committed_at - timedelta(minutes=5)
    bad = missing + future + early
    return {"entries": total, "missing": missing, "in_future": future, "before_commit": early,
            "value": round(1 - bad / total, 4) if total else None}


def _factor(name: str, value: float | None, detail: str, warnings: list[str]) -> dict[str, Any]:
    return {"name": name, "weight": WEIGHTS[name], "status": "KNOWN" if value is not None else "UNKNOWN",
            "value": round(max(0.0, min(1.0, value)), 4) if value is not None else None, "contribution": None, "detail": detail,
            "warnings": warnings}


def validate(records: list[dict[str, Any]], *, expected_dataset_hash: str | None, expected_count: int | None,
             layers_available: dict[str, dict[str, Any]], now: datetime, snapshot_committed_at: datetime | None = None,
             chain_intact: bool | None = None, truncated: bool = False) -> dict[str, Any]:
    """Every quality factor, the score, the status and the reasons for it. Pure: reads nothing but its arguments."""
    if not records:
        return {"status": UNKNOWN, "quality_score": None, "confidence": 0.0, "factors": [], "warnings": [],
                "reasons": ["The dataset has no records: there is nothing to validate."], "limitation": LIMITATION, "model_version": MODEL_VERSION,
                "records": 0}
    check = integrity.verify(records, expected_dataset_hash, expected_count)
    complete = quality.completeness(records)
    traced = provenance.evaluate(records, layers_available)
    consistent = quality.consistency(records)
    unique = duplicates.find(records)
    balanced = balance.evaluate(records)
    timed = timestamps(records, now, snapshot_committed_at)

    integrity_ok = check["status"] == "VERIFIED" and chain_intact is not False
    integrity_warnings = []
    if check["altered_count"]:
        integrity_warnings.append(f"{check['altered_count']} record(s) no longer match their stored hash.")
    if not check["dataset_hash_matches"] or not check["record_count_matches"]:
        integrity_warnings.append("The set of records does not match the dataset hash: records were added, removed or altered.")
    if chain_intact is False:
        integrity_warnings.append("The version chain is broken: an earlier version is missing or does not match its recorded hash.")
    factors = [
        _factor("integrity", 1.0 if integrity_ok else 0.0,
                f"{check['records_checked']} record hash(es) and the dataset hash were recomputed with {integrity.ALGORITHM}.", integrity_warnings),
        _factor("completeness", complete["value"], f"{complete['filled']} of {complete['cells']} feature and label cells hold a value.",
                [f"No record has a value for: {', '.join(complete['fields_fully_missing'])}."] if complete["fields_fully_missing"] else []),
        _factor("provenance", traced["value"],
                f"{traced['fields_traced']} of {traced['fields_known']} known fields are traceable to a source; "
                f"{traced['source_diversity']} of {len(provenance.LAYERS)} analysis layers contributed.",
                [f"No data from: {', '.join(traced['source_layers_missing'])}."] if traced["source_layers_missing"] else []),
        _factor("consistency", consistent["value"],
                f"{consistent['invalid_records']} record(s) break the schema and {consistent['inconsistent_records']} contradict themselves.",
                [f"{consistent['invalid_records'] + consistent['inconsistent_records']} suspicious record(s) need review."]
                if consistent["invalid_records"] + consistent["inconsistent_records"] else []),
        _factor("uniqueness", unique["value"],
                f"{unique['exact_duplicate_records']} exact duplicate(s), {unique['repeated_identity_records']} repeated identit(ies), "
                f"{unique['label_conflict_records']} record(s) with conflicting labels.",
                [f"{unique['label_conflict_records']} record(s) have identical features but different labels."] if unique["label_conflict_records"] else []),
        _factor("balance", balanced["value"], balanced["note"] or f"The smaller class is {balanced['minority_share']:.1%} of the labelled records.",
                [balanced["note"]] if balanced["note"] else []),
        _factor("timestamps", timed["value"], f"{timed['entries']} source timestamp(s) checked.",
                [f"{timed['missing']} missing, {timed['in_future']} in the future, {timed['before_commit']} before the analysed commit."]
                if timed["value"] is not None and timed["value"] < 1 else []),
    ]
    evaluated = [factor for factor in factors if factor["status"] == "KNOWN"]
    weight = sum(factor["weight"] for factor in evaluated)
    for factor in evaluated:
        factor["contribution"] = round(100 * factor["weight"] * factor["value"] / weight, 1)
    score = round(sum(factor["contribution"] for factor in evaluated), 1)
    sufficiency = min(1.0, len(records) / SUFFICIENT_RECORDS)
    confidence = round(weight / sum(WEIGHTS.values()) * sufficiency, 2)
    warnings = [warning for factor in factors for warning in factor["warnings"]]
    if truncated:
        warnings.append("The dataset was cut at the configured record limit; packages beyond it are not represented.")

    reasons: list[str] = []
    if not integrity_ok:
        status = INVALID
        reasons.append("Integrity verification failed: stored content does not match its hashes.")
    elif consistent["invalid_records"]:
        status = INVALID
        reasons.append(f"{consistent['invalid_records']} record(s) break the schema.")
    elif len(records) < MIN_RECORDS or confidence < 0.5 or score < 50:
        status = LOW_CONFIDENCE
        if len(records) < MIN_RECORDS:
            reasons.append(f"Only {len(records)} record(s); at least {MIN_RECORDS} are needed.")
        if confidence < 0.5:
            reasons.append(f"Confidence is {confidence}: too little of the quality model could be evaluated on a dataset this size.")
        if score < 50:
            reasons.append(f"The quality score is {score}.")
    elif score < 80 or warnings:
        status = WARNING
        reasons.append(f"The quality score is {score}." if score < 80 else "The checks pass, with the weaknesses listed.")
    else:
        status = VALID
        reasons.append("Every check passes and the score is at least 80.")
    return {
        "status": status, "quality_score": score, "confidence": confidence, "factors": factors, "warnings": warnings, "reasons": reasons,
        "records": len(records), "integrity": check, "chain_intact": chain_intact, "completeness": complete, "provenance": traced,
        "consistency": {k: v for k, v in consistent.items() if k != "suspicious"}, "suspicious_records": consistent["suspicious"],
        "duplicates": unique, "balance": balanced, "timestamps": timed, "truncated": truncated,
        "limitation": LIMITATION, "model_version": MODEL_VERSION,
    }

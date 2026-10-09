# Phase 10 — Self-validating security dataset

Model `dataset-quality-v1`. Code: `backend/app/analyzers/dataset/`,
`backend/app/services/datasets.py`, `backend/app/api/datasets.py`.

## 1. What it does

The platform's analysis results for a snapshot are also a dataset: one record
per dependency, with features, labels and the provenance of every field. This
phase builds that dataset, hashes it, stores it as an immutable version, and
measures how far it can be relied on.

**The checks find damage, gaps, duplicates and contradictions. They cannot
establish that the data is free of deliberate manipulation.** A well-formed,
consistent record can still be wrong at its source. No status means "clean"
or "poison-free", and none is worded that way.

## 2. Records

| Part | Fields |
|---|---|
| `identity` | ecosystem, name, version, package URL |
| `features` | `relationship`, `depth`, `dependents`, `dependencies`, `version_resolved`, `vulnerability_count`, `max_severity`, `reachability_state`, `fragility_score`, `graph_risk`, `predictive_risk`, `attack_path_count`, `max_attack_path_score` |
| `labels` | `vulnerable`, `reachable_vulnerability`, `risk_level` |
| `provenance` | per contributing layer: source collection, reference, collection time, basis |

A field whose layer has not been analysed is `null`. It is a gap, counted
under completeness; it is never filled with a default. At most
`DATASET_MAX_RECORDS` (30 000) records are built; a larger inventory is
truncated and reported.

Labels are the platform's own outputs (for example `vulnerable` means "a
published advisory matches this version"). They are not independent ground
truth, and the dataset documents this.

## 3. Integrity

SHA-256 throughout, over a canonical form: UTF-8 JSON, object keys sorted, no
insignificant whitespace, timestamps as UTC ISO 8601 with milliseconds.

| Hash | Covers |
|---|---|
| record hash | `record_id`, `identity`, `features`, `labels`, `provenance` |
| dataset hash | every record id with its record hash, in sorted order |
| chain hash | this version's dataset hash and the previous version's chain hash |

Versions are write-once. A change in the underlying results produces a new
version linked to the previous one, so an altered or removed earlier version
is detectable from any later one. **Validation always reads the records back
from storage**, so it checks what is stored rather than what was just
computed. `GET …/datasets/{id}` recomputes the hashes at request time.

The hashes detect change. They are not signatures: the digests live in the
same database as the records, so someone able to rewrite both consistently
would not be detected.

## 4. Quality factors

```text
quality_score = 100 × Σ(weight × value of evaluated factors) / Σ(weight of evaluated factors)
```

| Factor | Weight | Measures |
|---|---|---|
| integrity | 25 | every record and the dataset still match their hashes |
| completeness | 20 | share of feature and label cells that hold a value |
| provenance | 15 | fields traceable to a source; how many of the seven layers contributed |
| consistency | 15 | records free of schema, range and cross-field problems |
| uniqueness | 10 | records that are not duplicates and do not contradict each other |
| balance | 10 | representation of the smaller labelled class (balanced at 20 %) |
| timestamps | 5 | source times present, not in the future, not before the commit they describe |

Duplicate detection reports exact duplicates, repeated identities,
indistinguishable records and identical features with conflicting labels.
Confidence is reduced for datasets of fewer than 30 records, and fewer than
10 records are always `LOW_CONFIDENCE`.

## 5. Status

| Status | Meaning |
|---|---|
| `VALID` | the checks pass and the score is at least 80 |
| `WARNING` | usable, with stated weaknesses |
| `LOW_CONFIDENCE` | too small, too incomplete or too low-scoring to rely on |
| `INVALID` | integrity failed, or records break the schema |
| `UNKNOWN` | there is nothing to validate |

Every status comes with its reasons and with the limitation statement in
section 1.

## 6. API

| Method | Path | Result |
|---|---|---|
| POST | `/api/projects/{id}/datasets/validate` | 202 with the job: builds a version when results changed, then validates the stored records |
| GET | `/api/projects/{id}/datasets` | versions with status, score, hashes and chain state |
| GET | `/api/projects/{id}/datasets/{dataset_id}` | the version, a live hash verification, and its records (`suspicious`, `vulnerable` filters) |
| GET | `/api/projects/{id}/datasets/{dataset_id}/quality` | factors, problems, duplicate groups, distributions, validation history |

## 7. Storage

`datasets` (one document per version: hashes, schema version, contributing
layers), `dataset_records`, `dataset_quality` (one document per validation).
Records of older versions are pruned; their descriptions and hashes are kept
so the chain stays verifiable.

## 8. Tests

`backend/tests/test_datasets.py` — 56 tests: canonical hashing and its
stability across a database round trip, detection of an edited, added or
removed record and of a broken chain, each quality factor on seeded defects,
each status, immutability of versions, API contract and isolation.

## 9. Limitations

- One dataset per project snapshot, built from this platform's outputs. It
  inherits their limitations and is not a general-purpose benchmark.
- Labels are not independent ground truth.
- Manipulation that produces well-formed, consistent records is not
  detectable by these checks. Poisoning detection is not claimed.
- Suitability of the dataset for training a model has not been evaluated.

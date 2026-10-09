# Phase 12 — Final dashboard and reports

Code: `backend/app/services/{layers,overview,report}.py`,
`backend/app/api/overview.py`, `backend/app/api/dashboard.py`;
`frontend/src/pages/`, `frontend/src/components/platform/`,
`frontend/src/charts/PlatformCharts.tsx`, `frontend/src/graph/AttackGraph.tsx`.

## 1. One read of every layer

`services/layers.py` answers, once and from stored results only, "what do we
know, from which analysis, and how current is it". The reasoning engine, the
trust engine, the dashboards and the report all use it, so they cannot drift
apart. Each layer has a status:

| Status | Meaning |
|---|---|
| `ANALYSED` | results exist for the latest snapshot (or, for repository-level layers, for the repository) |
| `NOT_ANALYSED` | the layer has not been run |
| `STALE` | results exist only for an earlier snapshot |
| `UNAVAILABLE` | the layer ran but could not collect its data |

A layer that is not `ANALYSED` carries no figures. Nothing is filled in.

## 2. Dashboards

`/dashboard` shows the account summary and, for a selected project, three
views built from `GET /api/projects/{id}/overview`:

| View | Shows |
|---|---|
| **Executive** | trust score or **INSUFFICIENT DATA**, band, confidence, coverage and bounds; key counts (each "not analysed" rather than 0 when its layer has no result); trust and risk trend; what drives the risk; top cross-layer findings; recommended next steps |
| **Technical** | status of every layer; vulnerabilities by severity; reachability by status; predictive-risk, fragility and attack-path score distributions; behaviour timeline; inventory and SBOM; maintainers, dataset and findings |
| **Research** | layer coverage, trust-weight coverage, evidence grounding and unsupported-claim rate of the latest reasoning run, dataset quality (all measured on this project, none a benchmark result); models in use; evidence confidence by component; execution time of the latest jobs; the evaluation catalogue, where every measure without a benchmark reads **NOT EVALUATED**; the trust weights with the statement that they are not statistically trained |

A chart for a layer without results is replaced by a "not available" panel
naming the analysis to run. An empty chart could be read as a clean result,
so none is drawn.

## 3. Project pages

| Route | Page |
|---|---|
| `/dashboard` | account summary and project dashboards |
| `/projects/:id` | overview with links to every layer and a list of what is not built |
| `/projects/:id/trust` | score, bounds, components, contributions, unknowns, explanation, history, comparison |
| `/projects/:id/dependencies`, `/graph` | inventory and dependency graph (Phase 2) |
| `/projects/:id/vulnerabilities` | advisory matches (Phase 3) |
| `/projects/:id/sbom` | SBOM, verification, history, diff (Phase 3) |
| `/projects/:id/reachability` | static reachability (Phase 4) |
| `/projects/:id/fragility` | dependency intelligence and risk graph (Phase 5) |
| `/projects/:id/attack-paths` | paths, combined graph (React Flow), what-if, path detail |
| `/projects/:id/maintainers` | repository profile, indicators, contributors, weekly activity |
| `/projects/:id/commits` | analysed commits, anomaly factors, findings, events, monitoring switch |
| `/projects/:id/ai-analysis` | cross-layer findings with statements, labels and evidence |
| `/projects/:id/dataset` | versions, hashes, quality factors, problems, records |
| `/projects/:id/report` | the report, with Markdown download |

Charts use Recharts (trust trend, component contribution, counts by
category, score distributions, commit timeline, weekly activity). Graphs use
React Flow (dependency graph, risk graph, attack graph). Every page has
loading, empty, not-analysed and error states, and labels values with their
basis: `OBSERVED`, `DERIVED`, `INFERRED`, `PREDICTED`, `RECOMMENDED`.

## 4. Report

`GET /api/projects/{id}/report` (`?format=json|markdown`). Seventeen
sections:

1. Executive Summary 2. Trust Score 3. Risk Score 4. Vulnerability Findings
5. SBOM Integrity 6. Dependency Fragility 7. Code Reachability 8. Attack
Paths 9. Maintainer Behaviour 10. Commit Behaviour 11. AI Cross-Layer
Findings 12. Dataset Quality 13. Predictive Indicators 14. Recommendations
15. Evidence 16. Methodology 17. Limitations

A statement is `{basis, text, evidence}`. `basis` is `OBSERVED`, `DERIVED`,
`PREDICTED`, `RECOMMENDED`, or `METHOD` for a statement about how the
platform works (which cites the model version or document that defines it).
`evidence` lists references into the report's evidence index, each resolving
to a stored record.

**The report is served only when every statement and every table row cites
evidence that exists in its index.** `report.unsupported` returns the
statements that do not; if that list is not empty the endpoint answers 500
instead of handing out a report with an unsupported claim. A section whose
layer was not analysed says so, citing the layer's status record, and gives
no figures.

Generating a report is recorded in the audit log. The Markdown form is served
as an attachment. Reports are generated on request from the current state;
they are not stored, and there is no PDF export.

## 5. API

| Method | Path | Result |
|---|---|---|
| GET | `/api/projects/{id}/overview` | layers, trust, distributions, top items, timeline, model versions |
| GET | `/api/projects/{id}/report` | the report as JSON or Markdown |
| GET | `/api/dashboard/summary` | account summary; a `trust` entry per project, with score fields only when a score exists |
| GET | `/api/dashboard/evaluation` | the evaluation catalogue (see `research-validation.md`) |

## 6. Tests

Backend: `tests/test_overview_report.py` and `tests/test_dashboard.py` (31
tests): every layer state in the overview, all seventeen sections with and
without data, that no statement is unsupported, that unknown layers produce
no figures, Markdown rendering, audit, isolation.

Frontend: `tests/platform.spec.ts` (49 browser tests) runs every new page and
the three dashboards against responses recorded from the real backend
(`backend/tests/record_ui_fixture.py`), including the not-analysed and
insufficient-data states.

One existing assertion was changed: `tests/analysis-status.spec.ts` asserted
that the project page says the trust score is "Phase 12 · not built". The
trust score now exists, so that assertion was replaced by assertions that the
page links to it and states that an unanalysed layer is unknown. No other
existing test was modified to pass.

## 7. Limitations

- Dashboards refresh by polling; there is no push channel.
- Reports are Markdown or JSON only.
- The frontend was verified in a sandbox with an esbuild bundle and the
  TypeScript compiler; the Vite production build was not run there (see
  `phase13.md`).

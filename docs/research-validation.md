# TrustChain-X — Research validation

This document states what the project investigates, what was built, how it
can be evaluated, and — with equal weight — what has **not** been shown.

Reading rule for the whole document: a number is reported only where it was
measured, and the conditions of the measurement are given beside it. Where no
benchmark exists the entry is **NOT EVALUATED**. No accuracy figure is claimed
for any component.

## 1. Research problem

Can the trustworthiness of a software project's supply chain be estimated
from several independent kinds of evidence at once, in a way that is
explainable, that states its own confidence, and that never presents missing
evidence as a good result?

Existing practice answers narrower questions separately: which dependencies
have published vulnerabilities; whether an SBOM is well-formed; how a project
is maintained. Each answer is useful and each is incomplete on its own. A
published vulnerability matters more when the affected code is reached, when
the package is hard to replace, and when the repository's change control is
weak; it matters less when none of that holds. The research problem is the
correlation, and the honesty of the result when some layers are unknown.

## 2. Research gap

The following is the gap as this project frames it. It is a working
hypothesis, not a finding of a literature review: **no systematic survey of
prior work was carried out as part of this implementation, and no claim of
novelty is made** for any contribution below. Each of the individual
techniques used here (dependency graphs, advisory matching, static call
graphs, graph centrality, commit heuristics, weighted scoring) is well
established.

1. Tools commonly report vulnerability presence without stating whether the
   affected functionality is reached, or treat "not shown reachable" as safe.
2. Scores are often opaque, and a layer with no data silently contributes
   zero risk.
3. Maintainer and commit signals are usually separate from dependency
   analysis, and are sometimes presented as judgements about people.
4. Outputs that combine layers rarely carry, per statement, a reference to
   the stored evidence it rests on.
5. Analysis results are rarely treated as a dataset whose integrity and
   provenance can themselves be verified.

What would turn this into an established gap: a structured comparison with
existing tools and published methods on the same repositories. That is
future work (section 11).

## 3. Proposed architecture

```text
GitHub repository (read as data; never cloned, built or executed)
   │
   ├─ Snapshot ─ Dependencies ─ Dependency graph                    Phase 2
   ├─ Advisory matching (OSV) ─ SBOM (CycloneDX) ─ verification     Phase 3
   ├─ Static code reachability (Python)                             Phase 4
   ├─ Fragility ─ graph risk ─ predictive dependency risk           Phase 5
   ├─ Attack-path simulation                                        Phase 6
   ├─ Maintainer behaviour indicators                               Phase 7
   ├─ Commit behaviour indicators and anomaly score                 Phase 8
   │
   ├─ layers.collect: one read of every layer, with status          Phase 12
   ├─ Cross-layer reasoning over cited evidence                     Phase 9
   ├─ Self-validating dataset of the results                        Phase 10
   └─ Trust engine ─ dashboards ─ evidence-backed report            Phases 11–12
```

Design principles, each enforced in code and tested:

- **Static only.** Repository content is parsed, never run.
- **Evidence labels.** Every value is `OBSERVED`, `DERIVED`, `INFERRED`,
  `PREDICTED` or `RECOMMENDED`.
- **Unknown is a value.** A layer is `ANALYSED`, `NOT_ANALYSED`, `STALE` or
  `UNAVAILABLE`; an unknown input is `null` with a reason, never 0.
- **Deterministic and versioned.** Every model has a version string; the same
  inputs give the same output; every score is stored with its terms.
- **Bounded.** Every search, parser and collector has explicit limits and
  reports truncation.

Detail: `architecture.md` and `phase3.md` to `phase13.md`.

## 4. Research contributions

Stated as what was built and what it allows to be studied. "Contribution"
here means a contribution of this project, not a claim of priority.

| # | Contribution | What was built | Status of evidence |
|---|---|---|---|
| 1 | Predictive Dependency Fragility | A per-dependency score from graph structure (fan-in, depth, centrality, concentration) and release position, with every factor stored and unknown factors excluded (`phase5.md`) | Implemented and tested for correctness of computation. Predictive value NOT EVALUATED |
| 2 | Predictive Graph Reasoning | Propagation of exposure through the dependency graph; indicators; a ranking of dependencies for attention (`phase5.md`) | Graph algorithms verified against brute-force references. Ranking quality NOT EVALUATED |
| 3 | Attack-Path Simulation | Evidence-carrying paths from the project to a matched vulnerability, with confidence as a product of step confidences and four statuses that never assert exploitability (`phase6.md`) | Implemented and tested. Path validity NOT EVALUATED |
| 4 | Maintainer Behaviour Fingerprinting | A repository-level profile and seven indicators from public metadata, each `OBSERVED` / `NOT_OBSERVED` / `UNKNOWN`, with no classification of persons (`phase7.md`) | Implemented and tested. Relation to outcomes NOT EVALUATED |
| 5 | Real-Time Security Behaviour Model | Polling-based analysis of commit diffs as text against rule patterns, and an anomaly score against the repository's own baseline using robust statistics (`phase8.md`) | Implemented and tested. Precision and recall NOT EVALUATED |
| 6 | Cross-Layer AI Security Reasoning | A rule engine over an evidence store, a validator that refuses ungrounded findings, and a guarded provider interface. **The shipped engine is deterministic; no language model is integrated** (`phase9.md`) | Grounding is enforced and measured per run. Finding correctness NOT EVALUATED |
| 7 | Self-Validating Security Dataset | Versioned, hash-chained records of the analysis results with seven quality factors and five statuses (`phase10.md`) | Detection of seeded defects tested. Detection of deliberate manipulation is not claimed |
| 8 | Integrated Software Trust Model | A weighted, explainable risk and trust score with coverage, confidence, bounds for unknowns, and `INSUFFICIENT_DATA` below a coverage minimum (`phase11.md`) | Arithmetic tested. **These weights are expert-defined initial weights and are not statistically trained.** Calibration NOT EVALUATED |

## 5. Algorithms

| Component | Algorithm | Complexity (n nodes, e edges) |
|---|---|---|
| Dependency graph | construction from manifests and lockfiles; direct / transitive classification | O(n + e) |
| Advisory matching | ecosystem-specific version ordering; affected-range evaluation | O(matches × ranges) |
| Reachability | AST parsing; conservative call graph; breadth-first search from entry points to affected symbols | O(n + e) on the code graph |
| Graph metrics | iterative depth, fan-in / fan-out, dependents closure, betweenness-style centrality | up to O(n × e) |
| Risk propagation | bounded propagation of exposure along reverse dependency edges | O(n + e) per source |
| Attack paths | breadth-first shortest chain; depth-first bounded enumeration of simple paths; product confidence | BFS O(n + e); DFS bounded by `ATTACK_PATH_MAX_EXPANSIONS` |
| Maintainer indicators | frequency, weekly series, gaps, sliding-window clusters, Herfindahl–Hirschman concentration | O(c log c) for c commits |
| Commit anomaly | rule matching over diff lines; median / MAD robust z-score against a baseline | O(lines × rules) |
| Reasoning | condition evaluation per rule; citation validation | O(findings × evidence) |
| Dataset | canonical JSON; SHA-256 record, dataset and chain hashes; duplicate grouping by hash | O(records) |
| Trust | weighted mean over known components; bounds | O(1) |

All are deterministic. None is learned from data.

## 6. Metrics

Defined in `backend/app/evaluation/metrics.py`; each returns `None` when
undefined for its input rather than a default.

| Group | Metrics | Applies to |
|---|---|---|
| Deterministic components | precision, recall, false-positive rate, false-negative rate, F1, coverage (share of cases decided), execution time, scalability of graph processing | advisory matching, reachability, attack paths, commit rules, maintainer indicators |
| Prediction | precision@k, nDCG (ranking quality), Spearman correlation with later-observed findings, Brier score and expected calibration error (calibration, confidence quality) | fragility, predictive risk, trust score |
| Reasoning | evidence grounding, unsupported-claim rate, evidence coverage | cross-layer findings |
| Dataset | duplicate-detection accuracy, label consistency, provenance completeness | dataset validation |

### Current state of every measure

| Component | Measure | State |
|---|---|---|
| Advisory matching | precision, recall, FPR, FNR | **NOT EVALUATED** — needs versions labelled by hand or by a second independent source |
| Code reachability | precision, recall | **NOT EVALUATED** — needs functions labelled reachable or not by review or dynamic traces |
| Code reachability | coverage | measured per run; 6 of 34 findings on the one repository in `phase13.md` were in a supported language, and none was decided |
| Attack paths | precision | **NOT EVALUATED** — needs paths labelled by security review |
| Attack paths | scalability | **NOT EVALUATED** as a reported result; `python -m app.evaluation.run --scalability` produces timings for the machine it runs on |
| Commit behaviour | precision, recall, FPR | **NOT EVALUATED** — needs commits labelled by reviewers |
| Maintainer behaviour | precision | **NOT EVALUATED** — needs repositories with documented incidents and matched controls |
| Fragility, predictive risk | ranking quality, correlation, calibration | **NOT EVALUATED** — needs historical snapshots with later outcomes |
| Trust score | calibration, confidence quality | **NOT EVALUATED** |
| Reasoning | evidence grounding, unsupported-claim rate, evidence coverage | measured per run (structural; see below). Correctness of findings **NOT EVALUATED** |
| Dataset | label consistency, provenance completeness | measured per run |
| Dataset | duplicate-detection accuracy | **NOT EVALUATED** on external data; seeded duplicates are detected in tests |
| Platform | execution time | measured per job on the installation; not a benchmark |

Per-run structural measurements from the single end-to-end run in
`phase13.md` (one repository, stand-in services, one machine): evidence
grounding 1.0, unsupported-claim rate 0.0, evidence coverage 0.14, dataset
quality 91.9, all layers analysed. These confirm that the mechanisms ran.
They are **not** accuracy results: grounding of 1.0 is guaranteed by the
validator and says nothing about whether a finding is right.

## 7. Evaluation methodology

How each claim should be tested. None of this has been carried out.

1. **Benchmark construction.** Select repositories across ecosystems and
   sizes, fixed at specific commits. Labels must come from a source
   independent of the platform.
2. **Deterministic components.** For advisory matching, compare with a second
   source on the same versions and resolve disagreements by hand. For
   reachability, label a sample of (vulnerability, project) pairs by manual
   review; report precision and recall with confidence intervals, and
   coverage separately, since most findings may be undecided.
3. **Prediction.** Take snapshots at time T, compute scores, and compare with
   advisories and incidents published in (T, T + Δ]. Report precision@k, nDCG
   and Spearman correlation against the baselines in section 8. The split
   must be temporal to avoid leakage.
4. **Behaviour indicators.** Use repositories with publicly documented
   supply-chain incidents and matched controls; report per-indicator rates in
   both groups. The expected base rate of indicators in healthy projects is
   high, and must be reported.
5. **Reasoning.** Have reviewers rate a sample of findings for correctness
   and usefulness, blind to severity; report agreement between reviewers.
6. **Trust score.** Sensitivity analysis over the weights; rank stability
   across weightings; if outcome data exist, calibration.
7. **Performance.** Time each layer over repositories of increasing size;
   report hardware.

Run a labelled file through the metric functions with
`python -m app.evaluation.run --benchmark labels.json`. The catalogue
function accepts benchmark results (value, benchmark name, sample size,
date), but storing results and serving them through
`GET /api/dashboard/evaluation` is not wired: the endpoint and the Research
dashboard read **NOT EVALUATED** for every accuracy measure until that is
added together with the first real benchmark.

## 8. Baselines

For a comparison to be meaningful, each component should be compared with a
simpler alternative on the same data. None of these comparisons has been run.

| Component | Baseline |
|---|---|
| Advisory matching | a second advisory source or scanner on the same inventory |
| Reachability | "every vulnerability in an imported package is reachable" and "none is" |
| Fragility / predictive risk | ranking by number of dependents alone; by release age alone; random order |
| Attack-path score | ranking by published severity alone |
| Commit anomaly | size-only threshold; rules without a baseline |
| Trust score | equal weights; vulnerability count alone |

A component that does not outperform its baseline has not shown its value.

## 9. Limitations

- **Static analysis only.** Nothing is executed, so nothing about run-time
  behaviour, deployment or actual exploitability is known.
- **Known vulnerabilities only.** Unpublished weaknesses are not detected.
  The platform does not detect or predict zero-day vulnerabilities.
- **One advisory source** (OSV); one registry client each for PyPI and npm.
- **Reachability for Python only**, with a conservative call graph that does
  not resolve dynamic dispatch, reflection or generated code. Other languages
  are reported as unsupported.
- **Behaviour indicators are patterns in public metadata.** They do not
  identify intent, and they do not identify people as untrustworthy. Git
  authorship can be set freely.
- **Commit rules are textual.** They miss obfuscated or indirect code and
  flag ordinary code that resembles a pattern.
- **The reasoning engine is a rule set.** It finds the correlations it was
  written for. No language model is integrated; the provider guard does not
  verify that a cited fact is restated correctly.
- **Dataset validation detects damage, not deceit.** Well-formed, consistent
  manipulation is not detectable. Hashes are not signatures.
- **Weights and thresholds are judgement.** These weights are expert-defined
  initial weights and are not statistically trained. The same holds for the
  indicator weights, anomaly weights and normalisation curves.
- **No accuracy evaluation exists** for any component (section 6).
- **Verification environment.** The work was verified in a sandbox without
  Docker and without access to the live external services; see
  `phase13.md`, section 4.

## 10. Threats to validity

**Construct validity.** "Trust" is operationalised as a weighted mean of ten
component risks. Whether that corresponds to what a practitioner means by
trust is untested. Several components measure *uncertainty* (unresolved
versions, undecided reachability) and count it as risk; that is a design
choice, not an established relation.

**Internal validity.** Layers are not independent: attack-path risk is
computed from vulnerability and reachability results, and the dataset is
built from all of them. The trust score therefore counts some evidence more
than once. Renormalising over known components makes scores with different
coverage only loosely comparable. Dataset labels are the platform's own
outputs, so any evaluation that uses them as ground truth would be circular.

**External validity.** Development and the only end-to-end run used a small
number of repositories, chiefly one. Behaviour on large monorepos, other
ecosystems, or repositories without lockfiles may differ. Thresholds were
chosen by judgement on little data.

**Conclusion validity.** No statistical test has been run, and no sample
exists from which one could be. Any statement of the form "the score
predicts…" is unsupported at present.

**Reliability.** Results are deterministic for fixed inputs, but inputs
change: advisories are added and withdrawn, registries publish releases,
repositories receive commits. Results are stored with the time and versions
of their inputs for that reason.

**Verification.** Tests show that the code does what it is specified to do.
They do not show that the specification is right.

## 11. Future work

1. A labelled benchmark and the evaluation in section 7, starting with
   advisory matching and reachability, where independent labels are most
   attainable.
2. A structured comparison with existing tools and literature, to establish
   or reject the gap in section 2.
3. Sensitivity analysis of the trust weights; learning weights only if
   outcome data of sufficient size and quality exist.
4. Reachability for JavaScript/TypeScript and Java; additional advisory
   sources with conflict reporting.
5. A language-model provider behind the existing guard, with a content check
   of each sentence against its cited evidence, and a measured rate of
   refused output.
6. Self-healing SBOM (reconstruction from discovered SBOMs) and
   candidate-version comparison, both planned and not built.
7. Signed SBOMs, datasets and reports; webhook delivery of commits; a push
   channel for the interface.
8. Validation in the target deployment (Docker, live services) on a range of
   repositories.

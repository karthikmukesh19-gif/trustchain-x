# Phase 9 — Cross-layer AI security reasoning

Model `cross-layer-reasoning-v1`. Code: `backend/app/ai/`,
`backend/app/services/reasoning.py`, `backend/app/api/reasoning.py`.

## 1. What it does, and what "AI" means here

Correlates what the other layers stored into findings that no single layer
produces: for example a known vulnerability that static analysis shows is
reached by application code, in a package that is also fragile, in a
repository whose release control rests with one account.

**The reasoning engine that ships is deterministic.** It is a fixed set of
rules over stored evidence, with a deterministic provider that phrases each
explanation by joining the finding's own statements. No language model is
called, nothing leaves the platform, and no API key is needed.
`AI_PROVIDER` accepts only `deterministic`; any other value stops start-up.

The architecture is prepared for a language-model provider (the interface,
the prompt and the output guard exist and are tested), but none is
implemented. Section 6 describes the boundary such a provider would work
inside. Results labelled "AI findings" in the interface are the output of the
rule engine and are described as such on the page.

## 2. Evidence first

`evidence.py`. An evidence item is a pointer to a stored record (collection
and id) with a one-line summary and a basis (`OBSERVED`, `DERIVED`,
`INFERRED`, `PREDICTED`). `context.py` gathers one context from the layers'
stored results through `layers.collect` and registers every fact as an
evidence item (`E1`, `E2`, …, assigned in a stable order). Nothing is
analysed there and nothing is fetched from outside. A layer that has not been
analysed contributes no facts, and the rules see it as unknown.

Findings cite evidence by id. `evidence.validate` refuses a finding when:

- the finding, any of its statements, or its recommendation cites nothing;
- a citation does not resolve to an evidence item of this run, or a statement
  cites an item outside the finding's own evidence list;
- a statement labelled `OBSERVED` rests on evidence that is not observed;
- a statement has no valid label, or the recommendation is not labelled
  `RECOMMENDED`;
- the finding names a contributing layer it cites no evidence from;
- a text refers to an outside source ("according to…", "studies show…")
  without a citation.

A refused finding is not stored. The run records how many were refused.

## 3. Statement labels

| Label | Meaning |
|---|---|
| `OBSERVED` | read from the repository or an advisory source |
| `DERIVED` | computed from observed data by a documented analysis |
| `INFERRED` | a pattern match that usually means something (evidence basis only) |
| `PREDICTED` | a model's forward-looking estimate |
| `RECOMMENDED` | a suggested action; a judgement, not a fact |

## 4. Rules

Each rule evaluates conditions over the context and records which held, which
did not, and which could not be evaluated. A condition that could not be
evaluated is `UNKNOWN`: it never counts as "held" and never as "did not
hold". The per-rule trace is stored with the run.

| Category | Emitted when |
|---|---|
| `HIGH_PRIORITY_CORRELATED_RISK` | a known vulnerability is statically reachable **and** at least one other layer amplifies it (fragility, graph impact, a supported attack path, maintainer or commit indicators) |
| `REACHABLE_VULNERABILITY` | a known vulnerability is statically reachable |
| `FRAGILE_VULNERABLE_DEPENDENCY` | a known vulnerability in a package that is also fragile or hard to keep current |
| `UNVERIFIED_VULNERABILITY_EXPOSURE` | known vulnerabilities whose reachability is undetermined: a gap, not a clearance |
| `SECRET_EXPOSURE_REVIEW` | a commit added a value that looks like a credential |
| `CONCENTRATED_CHANGE_CONTROL` | concentrated maintenance together with pipeline or dependency-source changes |
| `ANOMALOUS_COMMIT_REVIEW` | commits that depart strongly from the repository's usual pattern |
| `SBOM_INTEGRITY_CONCERN` | the SBOM failed verification, or has not been verified |
| `DATASET_CONFIDENCE_LIMIT` | the dataset built from these results has known weaknesses |
| `INSUFFICIENT_EVIDENCE` | layers that have not been run, so their part of the picture is unknown |

Severities: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. No category names a
person, asserts an attack, or asserts exploitability.

## 5. Confidence

```text
confidence = weakest cited evidence × corroboration × completeness
```

| Term | Value |
|---|---|
| weakest evidence | lowest confidence among cited items (1.0 for a stored record that states none) |
| corroboration | 0.7 for one contributing layer, 0.85 for two, 1.0 for three or more |
| completeness | share of the rule's conditions that could be evaluated |

It is the confidence that the finding follows from the stored evidence. It is
not the likelihood of an attack.

## 6. Provider boundary and guard

`prompts.py` and `provider.py`. A provider is asked only to *rephrase* a
finding the rules already produced. It would be given that finding's
statements and the evidence they cite, and nothing else: no repository
content, no secrets, no other findings. Its answer is untrusted text and is
kept only if `provider.guard` accepts it:

- every sentence carries at least one citation, and every citation resolves
  to evidence the finding already cites;
- no over-claim: "exploit confirmed", "will be attacked", "guaranteed",
  "malicious maintainer", "zero-day" and similar are refused;
- length is bounded (1 500 characters).

On refusal the deterministic explanation is used and the refusal is recorded
in the finding's audit record. Because only the deterministic provider
exists, this path is exercised by tests with stand-in providers, not in
production.

## 7. Grounding metrics, measured per run

| Metric | Definition |
|---|---|
| `evidence_grounding` | share of statements citing at least one existing evidence item |
| `unsupported_claim_rate` | share of statements citing none |
| `evidence_coverage` | share of gathered evidence that at least one finding uses |
| `findings_rejected` | findings refused by validation |

These are structural measures of the stored output. For the deterministic
engine `unsupported_claim_rate` is 0 by construction (a finding with an
unsupported statement is not stored); the number confirms that the validator
ran, it is not an accuracy result. Whether the findings are *correct* has not
been evaluated against expert labels (NOT EVALUATED).

## 8. API

| Method | Path | Result |
|---|---|---|
| POST | `/api/projects/{id}/ai-analysis` | 202 with the job |
| GET | `/api/projects/{id}/ai-analysis` | `{job, snapshot, analysis, layers, total, items}`; filters `severity`, `category`, `layer` |
| GET | `/api/projects/{id}/ai-analysis/history` | earlier runs |
| GET | `/api/projects/{id}/ai-analysis/{finding_id}` | one finding with statements, evidence, conditions, confidence terms and audit record |

## 9. Storage

`analysis_runs` (kind `ai`) with the grounding metrics, the rule trace and the
state of every layer at the time; `ai_findings` with the findings and the
evidence items they cite.

## 10. Tests

`backend/tests/test_reasoning.py` — 49 tests: every rule with its conditions
held, not held and unknown; validation refusing each kind of ungrounded
finding; the guard refusing invented facts, missing citations and
over-claims; confidence terms; determinism; full-pipeline runs; API contract
and isolation.

## 11. Limitations

- Rules find the correlations they were written for. A combination nobody
  anticipated produces no finding.
- A finding inherits every limitation of the layers it cites.
- No language model is integrated, so there is no hallucination rate to
  report; the guard's behaviour with a real model is untested in practice.
- The guard checks that each sentence is cited and makes no forbidden claim.
  It does not check that the cited evidence actually supports the sentence:
  a model could misstate a cited fact (a wrong number, a wrong name) and pass.
  The prompt forbids this, but a prompt is not a control. A check of sentence
  content against evidence is required before any model provider is enabled.

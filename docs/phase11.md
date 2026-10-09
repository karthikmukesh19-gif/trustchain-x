# Phase 11 — TrustChain-X trust engine

Model `trust-v1`. Code: `backend/app/services/trust/`,
`backend/app/services/trust_service.py`, `backend/app/api/trust.py`.

## 1. What it does

Joins the layers into one explainable figure: a **risk score** and a **trust
score** (`100 − risk`), each 0–100, with the confidence, the coverage, the
bounds the unknowns leave, and the contribution of every component.

The trust score summarises the stored evidence about a snapshot under stated
weights. It is not a certification, and a high score is not a clean bill of
health: it reflects only what was analysed.

## 2. Weights

**These weights are expert-defined initial weights and are not statistically trained.**

They were set by judgement, not fitted to outcome data. A different weighting
is a legitimate choice and would give a different score from the same
evidence. The statement above is returned by every trust endpoint and shown
on the trust page and in the report.

| Component | Weight | Reads layer |
|---|---|---|
| Dependency risk | 15 | inventory |
| SBOM integrity | 15 | sbom |
| Vulnerability exposure | 15 | vulnerabilities |
| Code reachability | 10 | reachability |
| Dependency fragility | 10 | fragility |
| Attack-path risk | 10 | attack_paths |
| Maintainer behaviour | 10 | maintainers |
| Commit behaviour | 5 | commits |
| Dataset confidence | 5 | dataset |
| Predictive risk | 5 | predictive |
| **Total** | **100** | |

## 3. Component risk (0–100)

`normalization.py`. Each component is `KNOWN` with a risk and a confidence, or
`UNKNOWN`. A component is `UNKNOWN` when its layer has not been analysed, is
stale (results exist only for an earlier snapshot), or could not collect its
data. **An `UNKNOWN` component has no risk value: never 0, never a default.**

| Component | Risk |
|---|---|
| Dependency risk | weighted share of packages with no resolved version, unknown or inferred relationship, or no path from the project |
| SBOM integrity | 100 if verification failed; otherwise 30 × share of components with no resolved version; unknown if never verified |
| Vulnerability exposure | `100 × (1 − Π(1 − w))` over matches, w by published severity (CRITICAL 0.5, HIGH 0.3, MEDIUM 0.15, LOW 0.05, unknown 0.15) |
| Code reachability | mean over findings of REACHABLE 1.0, UNKNOWN / UNSUPPORTED 0.5, NOT_CONFIRMED_REACHABLE 0.1; 0 when no advisory matches |
| Dependency fragility | `0.5 × mean + 0.5 × highest` fragility score |
| Attack-path risk | the highest attack-path score |
| Maintainer behaviour | the attention score |
| Commit behaviour | `0.6 × highest + 0.4 × mean` anomaly score over recent analysed commits |
| Dataset confidence | `100 − quality score × confidence`; 100 if the dataset is `INVALID` |
| Predictive risk | mean of the highest predictive-risk scores |

Note that undecided reachability counts as half, not as nothing, and that an
unverified SBOM is unknown, not passed.

## 4. Calculation

```text
risk_score  = Σ(weight × component risk) / Σ(weight)        over the KNOWN components
trust_score = 100 − risk_score
coverage    = Σ(weight of KNOWN components) / 100
confidence  = coverage × Σ(weight × component confidence) / Σ(weight)   over the KNOWN components
```

Missing components are handled in three ways at once, so that an unknown is
never mistaken for a good result:

1. The score is an average over what is known. An unknown component neither
   lowers nor raises it.
2. Bounds are reported beside it: `risk_low` assumes every unknown component
   is at 0, `risk_high` assumes each is at 100. The distance between them is
   the room the unknowns leave.
3. When coverage is below `TRUST_MIN_COVERAGE` (default 0.6), **no score is
   given at all**: the status is `INSUFFICIENT_DATA`, `trust_score` and
   `risk_score` are `null`, and the interface shows **INSUFFICIENT DATA** with
   the layers to run. Showing a score then would present missing evidence as
   if it were good news.

Bands, for a scored result: `LOW_RISK` (trust ≥ 80), `MODERATE_RISK` (≥ 60),
`ELEVATED_RISK` (≥ 40), `HIGH_RISK`. A band describes the score, not the
software.

## 5. Explanation

`explanation.py` returns, in words: how the score was calculated, the
components ordered by contribution, every unknown component with the reason
and how to resolve it, and `RECOMMENDED` actions for components whose
contribution is material. Each component points at the stored record it was
read from. `GET …/trust` also reports whether the layers still look as they
did when the score was calculated (`is_current`).

## 6. API

| Method | Path | Result |
|---|---|---|
| POST | `/api/projects/{id}/trust/analyze` | 202 with the job |
| GET | `/api/projects/{id}/trust` | current result, model, weights and their statement |
| GET | `/api/projects/{id}/trust/history` | score series |
| GET | `/api/projects/{id}/trust/compare?base=&target=` | change per component; a delta only where both values are known |
| GET | `/api/projects/{id}/trust/explanation` | the explanation |

## 7. Storage

`trust_scores`: one document per calculation with every component, the
weights used, the model version and the layer state it was computed from.

## 8. Tests

`backend/tests/test_trust.py` — 50 tests: the weights and their statement,
each normaliser including its unknown cases, the arithmetic by hand,
`INSUFFICIENT_DATA` below the coverage minimum, bounds, that an unknown
component never improves the score, that a failed SBOM verification lowers
trust, history and comparison, API contract and isolation.

## 9. Limitations

- The weights and the normalisation curves are judgement. The score has not
  been calibrated or validated against outcomes (NOT EVALUATED).
- Renormalising over known components means two projects with different
  coverage are not strictly comparable; coverage and bounds are shown for
  that reason.
- The score describes a snapshot. A new commit makes it stale, and it is then
  shown as history.

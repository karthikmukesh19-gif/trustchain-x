# Phase 6 — Attack-path simulation

Model `attack-path-v1`. Code: `backend/app/analyzers/attack_paths/`,
`backend/app/services/attack_paths.py`, `backend/app/api/attack_paths.py`.

## 1. What it does

For every package of the latest snapshot that a published advisory matches,
and for every distinct vulnerability matched to it, one path is built from
evidence that earlier phases already stored:

```text
ENTRY → DEPENDENCY … → VULNERABILITY → REACHABILITY → APPLICATION → DOWNSTREAM_COMPONENT → IMPACT
```

A path states what could be traversed **if** the advisory's weakness were
exploitable in this context. Whether it is exploitable is never established
here.

**This is a static simulation.** Nothing contacts the repository, no code is
run, no request is sent to any target, and no exploit is attempted or
generated. `exploit_confirmed` is `false` on every path, by construction: the
platform has no means of confirming one.

## 2. Inputs

| Input | From | If missing |
|---|---|---|
| Dependency graph (nodes, edges, relationship basis) | Phase 2 | the analysis cannot start (409) |
| Advisory matches with state `AFFECTED` | Phase 3 | the analysis cannot start (409) |
| Reachability findings | Phase 4 | the reachability step is `NOT_ANALYSED`; the path is `UNKNOWN_PATH` |
| Fragility and graph-risk rows | Phase 5 | the graph-impact term uses graph structure only |

## 3. Nodes and edges

Node stages: `ENTRY`, `DEPENDENCY`, `VULNERABILITY`, `REACHABILITY`,
`APPLICATION`, `DOWNSTREAM_COMPONENT`, `IMPACT`. Every node carries the
evidence it rests on (collection and id of the stored record) and a basis:
`OBSERVED`, `DERIVED` or `INFERRED`. The `IMPACT` node is always `INFERRED`:
it restates the weakness class the advisory publishes and is labelled as
potential.

Edge kinds: `DECLARES`, `REQUIRES`, `AFFECTED_BY`, `ASSESSED_AS`, `USED_IN`,
`PROPAGATES_TO`, `MAY_RESULT_IN`. Each edge has a confidence in [0, 1]:

| Step | Confidence |
|---|---|
| Relationship read from a lockfile or manifest (`OBSERVED`) | 1.0 |
| Relationship derived by rule (`INFERRED`) | 0.8 |
| Relationship of unknown basis | 0.6 |
| Advisory match or reachability finding labelled HIGH / MEDIUM / LOW | 1.0 / 0.8 / 0.6 |
| Reachability undecided or not analysed | 0.5 |

A path's confidence is the **product** of its edges' confidences, so one weak
step lowers the whole path and no step can raise it. The steps that lowered
it are listed with the path.

## 4. Search

`path_engine.py`: breadth-first search for the shortest dependency chain from
the project to the package; depth-first search for alternative chains. Both
are iterative, never revisit a node on the current path (cycle protection),
and stop at explicit limits, recording that they did so:

| Setting | Default | Bounds |
|---|---|---|
| `ATTACK_PATH_MAX_DEPTH` | 12 | dependency steps in one path |
| `ATTACK_PATH_MAX_PATHS` | 500 | paths stored per analysis |
| `ATTACK_PATH_MAX_ROUTES` | 3 | chains listed per path |
| `ATTACK_PATH_MAX_EXPANSIONS` | 20 000 | search steps per vulnerable package |
| `ATTACK_PATH_GRAPH_MAX_NODES` | 400 | nodes in the combined graph view |

A result cut short by a limit is marked `truncated`, with what was left out.

## 5. Status

| Status | Meaning |
|---|---|
| `SUPPORTED_PATH` | Every step is backed by stored evidence, including static evidence that application code refers to the affected functionality. Exploitability was not tested |
| `POTENTIAL_PATH` | Chain and advisory match observed; static analysis found no application code that reaches the affected functionality |
| `UNKNOWN_PATH` | Chain and advisory match observed; whether application code reaches the affected functionality is unknown |
| `OBSERVED_COMPONENT` | The affected package is in the inventory, but no chain from the project to it is known |

There is no "confirmed" or "exploitable" status.

## 6. Score

```text
attack_path_score = vulnerability_signal × reachability_signal × graph_impact × confidence        (0–100)
```

| Term | Range | Source |
|---|---|---|
| `vulnerability_signal` | 0–100 | severity as published by the advisory source. `UNKNOWN` is the midpoint, never zero |
| `reachability_signal` | 0–1 | what static reachability established. Never zero: "not confirmed" is not "safe" |
| `graph_impact` | 0–1 | 0.4 for being in the graph, up to 0.3 for closeness to the project, up to 0.3 for what depends on it |
| `confidence` | 0–1 | product of step confidences |

The score orders paths for review. It is **not** a probability of attack and
not a statement that the weakness can be exploited. All four terms are stored
with each path, so the score can be recomputed by hand.

## 7. Break points and what-if

Each path lists `RECOMMENDED` changes that would remove it: upgrade to a
version the advisory lists as fixed (or, when it lists none, review whether
the package can be replaced), and review the direct dependency through which
the package arrives.
`choke_points` ranks packages by how many paths pass through them.
`GET …/attack-paths/graph?without=<node>` answers "what would remain if this
package no longer carried a path" — a static what-if over the stored graph,
not a prediction.

## 8. API

| Method | Path | Result |
|---|---|---|
| POST | `/api/projects/{id}/attack-paths/analyze` | 202 with the job; 409 without a snapshot, without a vulnerability check, or while another job runs |
| GET | `/api/projects/{id}/attack-paths` | `{job, snapshot, analysis, total, skip, limit, items}`; filters `status`, `level`, `severity`, `q` |
| GET | `/api/projects/{id}/attack-paths/graph` | combined graph, bounded; `?without=` for the what-if |
| GET | `/api/projects/{id}/attack-paths/history` | earlier analyses |
| GET | `/api/projects/{id}/attack-paths/{path_id}` | one path with nodes, edges, evidence, score terms, alternatives, break points |

## 9. Storage

`analysis_runs` (kind `attack_paths`) holds one document per analysis;
`attack_paths` holds the paths, keyed by `analysis_id` + `attack_path_id`. A
run is visible only once every row is stored. An analysis whose inputs are
unchanged (same input digest) is reused.

## 10. Tests

`backend/tests/test_attack_paths.py` — 85 tests: both searches on constructed
graphs (shortest path, every simple path, cycles, a very deep graph), every
limit and its truncation report,
confidence propagation, each status, score terms and monotonicity, determinism,
what-if, API contract, isolation between users, and that no status or text
claims a confirmed exploit.

## 11. Limitations

- A path is as good as its inputs: one advisory source, a reachability
  analysis for Python only, and a dependency graph that is partly inferred
  when a repository has no lockfile.
- No path beyond the dependency and reachability evidence is modelled:
  network exposure, deployment, authentication and configuration of the
  running system are not known to the platform.
- The score's terms are stated heuristics. Path validity has not been
  measured against paths labelled by security review (NOT EVALUATED).

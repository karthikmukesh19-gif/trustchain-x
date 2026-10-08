# Code Reachability Analysis (Phase 4)

Phase 3 says which dependency versions an advisory lists as affected. Phase 4
asks the next question: **does the application's own source code statically
reach the functionality the advisory identifies as affected?**

> **Static reachability is not exploitability.** A path in a conservative
> static graph is evidence that the source text refers to affected
> functionality. It does not show that an attacker can reach it, supply the
> input it needs, or trigger the flaw. And the absence of a path is not
> evidence of safety.

## What this phase does not do

- No exploitability prediction, no risk score, no trust score.
- No claim of a complete call graph or of semantic understanding of the code.
- No analysis of dependency source code: only the application's repository is read.
- No language other than Python.
- No invention of affected functions. If an advisory does not publish them
  and the operator has not supplied them, the answer is `UNKNOWN`.

## Pipeline

```text
POST /code-reachability/analyze  → job code_reachability_analysis
  SOURCE_INVENTORY  choose source files from the snapshot's file listing
  SOURCE_PARSING    fetch each by git blob id and parse it (never run it)
  GRAPH_BUILDING    map imports to dependencies; build the code graph
  SYMBOL_MAPPING    affected functions per advisory (advisory or operator file)
  REACHABILITY      search the graph for each vulnerability match; store findings
```

Input: the Phase 2 snapshot (file listing with blob ids, resolved
dependencies) and the Phase 3 vulnerability matches with status `AFFECTED`.
The job needs both a snapshot and a vulnerability check for that snapshot.

Modules:

| Module | Role |
|---|---|
| `analyzers/source/base.py` | `SourceAnalyzer` interface and record shapes. A new language is a new subclass registered in `analyzers/source/__init__.py` |
| `analyzers/source/inventory.py` | which files are analysed, and why the others are not |
| `analyzers/source/python_ast.py` | Python analysis with the standard `ast` module |
| `analyzers/reachability/imports.py` | import name → dependency |
| `analyzers/reachability/callgraph.py` | cross-file resolution and the graph |
| `analyzers/reachability/symbols.py` | affected symbols from advisories and the operator file |
| `analyzers/reachability/engine.py` | path search and the status decision |
| `services/reachability.py`, `api/reachability.py` | job, persistence, API |

## Source inventory

Files are taken from the snapshot's listing; contents are fetched through the
GitHub API by blob id and verified against that id, so they are exactly the
snapshot's commit. Source text is not stored: only what was extracted from it
and short evidence lines (200 characters).

| Selection | Meaning | Makes the analysis incomplete |
|---|---|---|
| `SELECTED` | fetched and parsed | |
| `SKIPPED_IGNORED_DIRECTORY` | under `node_modules`, `vendor`, `third_party`, `site-packages`, `.venv`, `venv`, `__pycache__`, `.tox`, … (other people's code or caches) | no |
| `SKIPPED_GENERATED` | `*_pb2.py`, `*_pb2_grpc.py` | no |
| `SKIPPED_TOO_LARGE` | above `REACHABILITY_MAX_FILE_BYTES` | yes |
| `SKIPPED_FILE_LIMIT`, `SKIPPED_SIZE_LIMIT` | beyond the file-count or total-size limit (application code is kept before tests, shallow paths before deep ones) | yes |
| `SKIPPED_UNSUPPORTED_FORMAT` | Python in a form that is not parsed: notebooks (`.ipynb`), Cython (`.pyx`) | yes |
| `SKIPPED_UNSAFE_PATH`, `FETCH_FAILED` | unusable path; blob no longer available | yes |

Directories such as `build`, `dist`, `env` or `out` are **not** skipped: they
can be real packages, and silently skipping application code would make "no
path found" wrong.

Parse status per file: `PARSED`, `SYNTAX_ERROR` (including Python 2),
`NOT_TEXT` (binary, NUL bytes, undecodable), `TOO_COMPLEX` (node or nesting
limit). A file that fails never fails the job; it makes the analysis
incomplete.

## Python analysis

`ast.parse` builds a syntax tree. The source is never compiled to run,
imported, evaluated or executed.

Extracted per file:

- **Symbols** with stable identities: module `app.services.user`, function
  `app.services.user:create_user`, class `app.services.user:UserService`,
  method `app.services.user:UserService.create_user`, nested
  `…:outer.<locals>.inner`. Each has path, line, end line, column, parent,
  decorators and base classes. The module identity is the repository path.
- **Imports**: `import x`, `import x.y`, `import x as y`, `from x import y`,
  `from x.y import z as w`, relative imports, star imports, and literal
  `importlib.import_module("x")` / `__import__("x")`.
- **Usages**: every call, every bare decorator and every reference to an
  imported or local name, with what the name is *statically bound to* in that
  file.

Binding follows Python's scoping for the cases that can be decided from the
text: parameters, definitions, imports, enclosing scopes, class bodies,
comprehension and lambda variables. A name is bound with certainty only if
its scope binds it exactly one way. Otherwise:

| Situation | Result |
|---|---|
| Parameter, loop variable, `except … as`, `del`, pattern capture, walrus, reassigned variable | unresolved (`UNKNOWN_RECEIVER`) |
| Imported on two branches (`try/except`, `if/else`), imported and also assigned, rebound through `global` elsewhere, or followed by a later star import | recorded for **each** candidate, marked `conditional` |
| `x = Thing()` once, then `x.method()` | `Thing.method`, marked `instance` |
| `f = pkg.func` once, then `f()` | `pkg.func`, marked `alias` |
| `self.method()` where the class defines `method` | that method, marked `self` |
| `self.other.method()`, an inherited method | unresolved (`SELF_ATTRIBUTE`) |
| `getattr(obj, name)`, `eval`, `exec`, `importlib.import_module(name)` | unresolved (`DYNAMIC_GETATTR`, `DYNAMIC_EVAL`, `DYNAMIC_IMPORT`) |
| A name a star import may supply | unresolved (`STAR_IMPORT`) |

## Import → dependency mapping

| Basis | Rule |
|---|---|
| `NAME_EQUAL` | the import's top-level name, normalised like a distribution name, equals a Python dependency of the snapshot |
| `KNOWN_IMPORT_NAME` | a short documented table of distributions whose import name differs (`yaml` → PyYAML, `jose` → python-jose, `dotenv` → python-dotenv, `PIL` → Pillow, `bson` → pymongo, …) and only if that distribution is in the inventory |

Both are inferences: nothing is installed, so the mapping is not read from
the package. Other outcomes: `LOCAL` (a module of the repository), `STDLIB`,
`UNMAPPED` (third-party, no matching dependency), `AMBIGUOUS` (two
distributions in the inventory could provide the name). Each import statement
is stored with file, line, text, the dependency and its resolved version.

A local module is matched from the importing file's directory and each of its
ancestors. A module never satisfies its own absolute import. Two candidates
are not chosen between.

## Code graph

Nodes: modules, classes, functions, methods, and **external** nodes for the
dependency names the code refers to (`requests.get`). External nodes have no
outgoing edges.

| Edge | Meaning |
|---|---|
| `imports` | a scope imports a local module or a dependency |
| `calls` | a call (or decorator application) whose callee was bound |
| `references` | a bound name used without being called (a callback, an assignment) |
| `constructs` | a class to its own `__init__` |

| Confidence | When |
|---|---|
| HIGH | bound by an explicit import or definition and called directly |
| MEDIUM | one inference: `self` method, re-export through a local module, alias, conditional binding, literal dynamic import, method of a local class on an instance |
| LOW | attribute of a call result on something external; a reference that is not a call |

Unresolved uses are stored with their reason and are never edges. The
standard library and unmapped packages stay outside the graph.

## Affected symbols

Two sources only:

1. **The advisory record**: `affected[].ecosystem_specific.affected_functions`
   and `affected[].ecosystem_specific.imports[].{path, symbols}` (also under
   `database_specific`).
2. **An operator mapping file** (`REACHABILITY_SYMBOL_MAPPINGS_FILE`, shipped
   empty): entries of `advisory_id`, `ecosystem`, `package`, `symbols`,
   an `https` `source_url` that justifies them, optional `aliases` and `note`.
   Invalid entries are ignored and reported. Results based on it are labelled
   `OPERATOR_SUPPLIED` and never exceed MEDIUM confidence.

```json
{"mappings": [{"advisory_id": "GHSA-xxxx-xxxx-xxxx", "ecosystem": "PyPI", "package": "example",
               "symbols": ["example.module.function"], "source_url": "https://github.com/example/example/pull/1"}]}
```

Nothing is derived from an advisory's title, description, references or patch.

**Observed limitation:** in the GitHub-reviewed advisory database examined
while building this phase (11,584 PyPI package entries), no entry published
affected functions. Without operator mappings, real Python findings are
therefore `UNKNOWN / SYMBOL_MAPPING_UNKNOWN`, with dependency-usage evidence.

A symbol counts as reached only on an **exact** match (the name itself, or a
member of an affected class or module). A use that merely shares the trailing
name (`torch.load` vs `torch.jit.load`, `requests.get` vs `requests.api.get`)
may be a re-export or a different function; it is reported as
`UNKNOWN / SYMBOL_MATCH_UNCERTAIN`. Write operator mappings with the name the
package is imported and used by.

## Reachability

Starting points: module-level code, and every function or method that nothing
in the analysed source calls or references (a possible entry point: a handler,
a command, a public function). Which of these really are entry points is not
known statically.

Search: breadth-first, backwards from the affected external nodes, so the
path found is a shortest one. Paths made only of HIGH edges are tried first,
then HIGH+MEDIUM, then any. A start in application code is preferred over one
in test code.

| Status | Reason | When |
|---|---|---|
| `REACHABLE` | `PATH_FOUND` | a path reaches an exactly matched affected name |
| `NOT_CONFIRMED_REACHABLE` | `NO_PATH_FOUND` | affected names known, source complete, no dynamic route, no path |
| `UNKNOWN` | `SYMBOL_MAPPING_UNKNOWN` | no affected names available |
| | `SYMBOL_MATCH_UNCERTAIN` | only a same-name use, or the affected names are not written with the package's import name |
| | `AMBIGUOUS_DEPENDENCY` | the import name also belongs to a local module or another package |
| | `IMPORT_MAPPING_UNKNOWN` | the package is not seen imported, but unmapped imports exist |
| | `DEPENDENCY_SOURCE_NOT_ANALYSED` | not imported by the application; installed for another package |
| | `INCOMPLETE_SOURCE` | no path, but some source was not analysed |
| | `DYNAMIC_CODE` | no path, but `eval`/`exec`, a computed import, `getattr` with a computed name on the package, or a star import of it |
| `UNSUPPORTED` | `LANGUAGE_NOT_SUPPORTED` | the dependency's ecosystem has no analyzer |

`UNKNOWN` is never converted into anything else, and no status means "safe".

**Confidence** describes evidence quality, not likelihood:

- `REACHABLE`: the weakest edge on the path; at most MEDIUM for an operator mapping.
- `NOT_CONFIRMED_REACHABLE`: HIGH if the package is never imported (and every
  import is explained); MEDIUM if imported and all its uses were bound
  directly; LOW if files using it also call objects of unknown type.
- `UNKNOWN`, `UNSUPPORTED`: none.

## Evidence model

Each finding (`code_reachability`) carries: project, repository, snapshot,
analysis, match and advisory ids; dependency, ecosystem, resolved version;
status, confidence, reason, explanation; `affected_symbols` and
`matched_symbol` with their origin; and

- `evidence` — source file, line, containing symbol, text, and the path as labels;
- `observed` — dependency usage (import and use sites), the full path with
  each edge's location and text, the usage path, dynamic sites;
- `inferred` — the conclusion and the inferences it rests on.

## Idempotency and reuse

One analysis per (project, snapshot, analyzer version). Running again replaces
its findings. Parsed source is reused for the same snapshot, so a re-run after
a new vulnerability check makes no GitHub requests; `{"refresh_source": true}`
forces a re-read. A run that fails leaves the previous results untouched.
Parsed source is kept for the project's current snapshot only; findings of
earlier snapshots are kept.

## Limits

| Setting | Default |
|---|---|
| `REACHABILITY_MAX_FILES` | 2000 |
| `REACHABILITY_MAX_FILE_BYTES` | 512 KiB |
| `REACHABILITY_MAX_TOTAL_BYTES` | 32 MiB |
| `REACHABILITY_MAX_NODES_PER_FILE` | 200,000 syntax nodes |
| `REACHABILITY_MAX_EDGES` | 300,000 |
| `REACHABILITY_TIMEOUT_SECONDS` | 600 |
| `REACHABILITY_SYMBOL_MAPPINGS_FILE` | empty (the packaged, empty file) |

One GitHub request is made per source file. Unauthenticated access allows 60
an hour; set `GITHUB_TOKEN`.

## Security controls

- Repository code is never executed, imported, installed or built; no shell
  command is constructed from repository content.
- Files are addressed by validated blob id, never by a path on disk; paths
  are validated and used only as labels.
- File count, file size, total size, syntax nodes, records per file,
  attribute-chain length, module-lookup steps, graph edges and run time are
  bounded. Malformed, binary, deeply nested or oversized input gives a status.
- Star-import chains are resolved once and loops end; lookup cost does not
  grow with attacker-chosen name lengths.
- Every endpoint is owner-scoped; ids are validated; search text is escaped.
- Job starts are rate limited and audited.

## Tests

`tests/test_source_analysis.py` (inventory and AST), `test_reachability_graph.py`
(mapping, graph, symbols, engine) and `test_reachability.py` (API, job,
persistence, isolation, failures); `frontend/tests/reachability.spec.ts`.
Fixtures include the reference example (`handle_request → fetch →
requests.get`), a negative case, and dynamic cases. Synthetic `TEST-*`
advisories are used where a published affected function is needed, because
real Python advisories do not provide one.

## Known limitations

- Python only; one repository; dependency source is not analysed.
- No type inference: calls on parameters, attributes of `self`, return
  values and containers are unresolved.
- Inherited methods, decorators that replace functions, monkey-patching,
  metaclasses and framework dispatch (routes, signals, tasks) are not modelled.
- Entry points are approximated by "nothing calls it".
- Import-name mapping is by name and a small table.
- Module-level objects imported from other modules (`from app.db import client`)
  are not followed.
- Accuracy has not been measured against a labelled benchmark.

## Extension points

- Another language: implement `SourceAnalyzer`, register it, add its
  ecosystem to `ECOSYSTEM_LANGUAGE`.
- Another symbol source: add a function beside `from_advisory` / `from_operator`.
- Entry-point models, type inference and dependency-source analysis would
  refine `callgraph.py` without changing the engine or the stored shapes.

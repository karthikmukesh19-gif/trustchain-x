"""Static analysis of Python source with the standard library's `ast` module.

The source is parsed into a syntax tree and read. It is never compiled to
bytecode, imported, evaluated or executed, and no name is looked up in the
running interpreter except the list of builtin names.

What is extracted is what the text of one file establishes on its own:
definitions, import statements, and for every call or reference the binding
of the name being used, following Python's scoping rules for the simple cases
(parameters, single assignments, imports, definitions). Anything that would
need the program's run-time state is reported as unresolved with a reason.
"""

from __future__ import annotations

import ast
import builtins
import posixpath
import warnings
from typing import Any

from app.analyzers.source import base
from app.analyzers.source.base import ParsedFile, SourceAnalyzer, SourceLimits

_BUILTINS = frozenset(dir(builtins))
_FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
_MAX_ALIAS_DEPTH = 6
_MAX_ATTRIBUTES = 24          # a.b.c... longer than this is not a name anyone imports


class _TooComplex(Exception):
    pass


class _Name:
    """Everything one scope does to bind a name. A use is resolved only when this leaves no doubt."""

    __slots__ = ("imports", "definition", "value", "assignments", "param", "outer", "other")

    def __init__(self) -> None:
        self.imports: list[tuple[str, str | None, int, int]] = []    # (module, imported name, level, line)
        self.definition: tuple[str, str] | None = None                # ("def" | "class", symbol id)
        self.value: ast.AST | None = None                             # the value of a single plain assignment
        self.assignments = 0
        self.param = False
        self.outer = False                                            # declared global / nonlocal here
        self.other = False                                            # bound some other way (loop, except, del, pattern, ...)

    def kinds(self) -> int:
        return (1 if self.imports else 0) + (1 if self.definition else 0) + (1 if self.assignments else 0) + (1 if self.param else 0) \
            + (1 if self.other else 0)


class _Scope:
    __slots__ = ("kind", "symbol", "parent", "bindings", "star", "star_lines", "class_id", "self_name", "class_names")

    def __init__(self, kind: str, symbol: str, parent: "_Scope | None", class_id: str | None = None, self_name: str | None = None) -> None:
        self.kind = kind                    # module | function
        self.symbol = symbol                # id of the module or function that owns the code in this scope
        self.parent = parent
        self.bindings: dict[str, _Name] = {}
        self.star = False                   # a "from x import *" is in effect
        self.star_lines: list[int] = []
        self.class_id = class_id            # for a method: the class it belongs to
        self.self_name = self_name          # for a method: the name of its first parameter
        self.class_names: frozenset[str] = frozenset()

    def name(self, identifier: str) -> _Name:
        record = self.bindings.get(identifier)
        if record is None:
            record = self.bindings[identifier] = _Name()
        return record


def _dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


class _FileAnalysis:
    def __init__(self, path: str, module: str, tree: ast.Module, lines: list[str], limits: SourceLimits) -> None:
        self.path, self.module, self.tree, self.lines, self.limits = path, module, tree, lines, limits
        self.symbols: list[dict[str, Any]] = []
        self.imports: list[dict[str, Any]] = []
        self.usages: list[dict[str, Any]] = []
        self.nodes = 0
        self.truncated = False
        self.class_methods: dict[str, set[str]] = {}

    # -- bookkeeping -------------------------------------------------------------------

    def _tick(self, amount: int = 1) -> None:
        self.nodes += amount
        if self.nodes > self.limits.max_nodes:
            raise _TooComplex

    def _room(self) -> bool:
        if len(self.symbols) + len(self.imports) + len(self.usages) >= self.limits.max_records:
            self.truncated = True
            return False
        return True

    def _text(self, node: ast.AST) -> str:
        line = getattr(node, "lineno", 0)
        if 0 < line <= len(self.lines):
            return self.lines[line - 1].strip()[: self.limits.max_text]
        return ""

    def _symbol(self, kind: str, qualname: str, node: ast.AST | None, parent: str | None) -> str:
        identity = f"{self.module}:{qualname}" if qualname else self.module
        if self._room():
            record: dict[str, Any] = {
                "id": identity, "kind": kind, "name": qualname.rsplit(".", 1)[-1] if qualname else self.module.rsplit(".", 1)[-1],
                "qualname": qualname, "module": self.module, "path": self.path, "parent": parent,
                "line": getattr(node, "lineno", 1) if node is not None else 1,
                "end_line": getattr(node, "end_lineno", None) if node is not None else (len(self.lines) or 1),
                "col": getattr(node, "col_offset", 0) if node is not None else 0,
                "decorators": [], "bases": [],
            }
            if node is not None:
                record["decorators"] = [self._expression_text(d) for d in getattr(node, "decorator_list", [])][:20]
                record["bases"] = [self._expression_text(b) for b in getattr(node, "bases", [])][:20]
            self.symbols.append(record)
        return identity

    def _expression_text(self, node: ast.AST) -> str:
        target = node.func if isinstance(node, ast.Call) else node
        return (_dotted(target) or self._text(node))[: self.limits.max_text]

    # -- bindings ----------------------------------------------------------------------

    def _statements(self, body: list[ast.stmt]):
        """Statements of one scope, including those nested in if/try/with/for blocks, but not in inner scopes."""
        stack = list(reversed(body))
        while stack:
            node = stack.pop()
            self._tick()
            yield node
            if isinstance(node, (*_FUNCTIONS, ast.ClassDef)):
                continue
            for name in ("body", "orelse", "finalbody", "handlers", "cases"):
                children = getattr(node, name, None)
                if isinstance(children, list):
                    stack.extend(reversed([c for c in children if isinstance(c, (ast.stmt, ast.ExceptHandler, ast.match_case))]))

    def _bind_target(self, scope: _Scope, target: ast.AST, value: ast.AST | None, plain: bool = True) -> None:
        """Record an assignment. `plain` is a single `name = value` statement; anything else leaves the value unknown."""
        if isinstance(target, ast.Name):
            record = scope.name(target.id)
            if plain and value is not None:
                record.assignments += 1
                record.value = value if record.assignments == 1 else None
            else:
                record.other = True
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self._bind_target(scope, element.value if isinstance(element, ast.Starred) else element, None, False)

    def _bind_import(self, scope: _Scope, bound: str, module: str, name: str | None, level: int, line: int) -> None:
        record = scope.name(bound)
        if not any(item[:3] == (module, name, level) for item in record.imports) and len(record.imports) < 8:
            record.imports.append((module, name, level, line))

    def _collect(self, scope: _Scope, body: list[ast.stmt], qualprefix: str) -> None:
        for node in self._statements(body):
            self._bind_expression_names(scope, node)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    bound = alias.asname or alias.name.split(".", 1)[0]
                    # "import a.b" binds "a"; "import a.b as c" binds c to the module a.b.
                    module = alias.name if alias.asname else alias.name.split(".", 1)[0]
                    self._bind_import(scope, bound, module, None, 0, node.lineno)
                    self._import(scope, alias.name, None, bound, 0, node)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    if alias.name == "*":
                        scope.star = True
                        scope.star_lines.append(node.lineno)
                        self._import(scope, module, None, None, node.level, node, star=True)
                        continue
                    bound = alias.asname or alias.name
                    self._bind_import(scope, bound, module, alias.name, node.level, node.lineno)
                    self._import(scope, module, alias.name, bound, node.level, node)
            elif isinstance(node, (*_FUNCTIONS, ast.ClassDef)):
                record = scope.name(node.name)
                identity = ("class" if isinstance(node, ast.ClassDef) else "def", f"{self.module}:{qualprefix}{node.name}")
                if record.definition is not None and record.definition != identity:
                    record.other = True
                record.definition = identity
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    self._bind_target(scope, target, node.value, len(node.targets) == 1)
            elif isinstance(node, ast.AnnAssign):
                self._bind_target(scope, node.target, node.value, node.value is not None)
            elif isinstance(node, (ast.AugAssign, ast.For, ast.AsyncFor)):
                self._bind_target(scope, node.target, None, False)
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        self._bind_target(scope, item.optional_vars, item.context_expr, True)
            elif isinstance(node, ast.ExceptHandler) and node.name:
                scope.name(node.name).other = True
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                for name in node.names:
                    scope.name(name).outer = True
            elif isinstance(node, ast.Delete):
                for target in node.targets:
                    self._bind_target(scope, target, None, False)
            elif isinstance(node, ast.match_case):
                for child in ast.walk(node.pattern):
                    self._tick()
                    captured = getattr(child, "name", None) if isinstance(child, (ast.MatchAs, ast.MatchStar)) else \
                        getattr(child, "rest", None) if isinstance(child, ast.MatchMapping) else None
                    if captured:
                        scope.name(captured).other = True

    def _bind_expression_names(self, scope: _Scope, statement: ast.AST) -> None:
        """name := value inside any expression of the statement binds the name in this scope."""
        stack = list(self._statement_expressions(statement))  # type: ignore[arg-type]
        while stack:
            node = stack.pop()
            self._tick()
            if isinstance(node, (*_FUNCTIONS, ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
                scope.name(node.target.id).other = True
            stack.extend(ast.iter_child_nodes(node))

    def _import(self, scope: _Scope, module: str, name: str | None, bound: str | None, level: int, node: ast.AST,
                star: bool = False, dynamic: bool = False) -> None:
        if self._room():
            self.imports.append({
                "scope": scope.symbol, "module": module, "name": name, "bound": bound, "level": level, "star": star,
                "dynamic": dynamic, "line": getattr(node, "lineno", 0), "col": getattr(node, "col_offset", 0),
                "statement": self._text(node),
            })

    # -- name resolution ---------------------------------------------------------------

    def _lookup(self, scope: _Scope, name: str) -> tuple[_Name | None, _Scope | None, bool]:
        """(binding record, scope that holds it, whether a star import could supply the name)."""
        star = False
        current: _Scope | None = scope
        while current is not None:
            record = current.bindings.get(name)
            if record is not None and record.kinds():
                return record, current, star
            star = star or current.star
            current = current.parent
        return None, None, star

    def _unresolved(self, reason: str, node: ast.AST, subject: dict[str, Any] | None = None) -> dict[str, Any]:
        target: dict[str, Any] = {"kind": "unresolved", "reason": reason, "expr": (_dotted(node) or self._text(node))[: self.limits.max_text]}
        if subject is not None and subject.get("kind") != "unresolved":
            target["subject"] = subject
        return target

    def _resolve(self, node: ast.AST, scope: _Scope, shadow: frozenset[str], depth: int = 0) -> dict[str, Any]:
        """What the expression `node` (a name, an attribute chain or a call) is statically bound to."""
        self._tick()
        if depth > _MAX_ALIAS_DEPTH:
            return self._unresolved(base.UNKNOWN_RECEIVER, node)
        attrs: list[str] = []
        current = node
        while isinstance(current, ast.Attribute):
            attrs.append(current.attr)
            current = current.value
        attrs.reverse()

        if isinstance(current, ast.Call):
            literal = self._literal_getattr(current, scope, shadow)
            if literal is not None:
                inner = literal
            else:
                inner = self._resolve(current.func, scope, shadow, depth + 1)
                if inner["kind"] not in ("import", "local") or not attrs:
                    return self._unresolved(base.CALL_RESULT, node, inner)
                inner = {**inner, "via": "instance"}
            return {**inner, "attrs": [*inner.get("attrs", []), *attrs]} if inner["kind"] in ("import", "local") \
                else self._unresolved(base.CALL_RESULT, node, inner)
        if not isinstance(current, ast.Name):
            return self._unresolved(base.UNKNOWN_RECEIVER, node)

        head = current.id
        if len(attrs) > _MAX_ATTRIBUTES:
            return self._unresolved(base.UNKNOWN_RECEIVER, node)
        if head in shadow or head in scope.class_names:
            return self._unresolved(base.UNKNOWN_RECEIVER, node)
        record, holder, star = self._lookup(scope, head)
        if record is None or holder is None:
            if head in _BUILTINS:
                return {"kind": "builtin", "name": head, "attrs": attrs}
            # Not bound in this file. If a star import is in effect the name may come from it.
            return self._unresolved(base.STAR_IMPORT if star else base.UNDEFINED_NAME, node)
        if record.imports:
            # Bound by an import. It is certain only if nothing else in the scope binds the same name: no second
            # import (try/except, if/else), no assignment, no later star import that could replace it.
            doubtful = record.kinds() > 1 or len(record.imports) > 1 or any(line > record.imports[0][3] for line in holder.star_lines)
            module, name, level, _line = record.imports[0]
            target: dict[str, Any] = {"kind": "import", "module": module, "name": name, "level": level, "attrs": attrs}
            if doubtful:
                target["via"] = "conditional"
                if len(record.imports) > 1:
                    target["alternatives"] = [{"module": m, "name": n, "level": lv} for m, n, lv, _ in record.imports[1:]]
            return target
        if record.kinds() > 1:
            return self._unresolved(base.UNKNOWN_RECEIVER, node)        # bound in more than one way: not known statically
        if record.definition is not None:
            return {"kind": "local", "symbol": record.definition[1], "attrs": attrs}
        if record.param:
            if holder.class_id and head == holder.self_name:
                if len(attrs) == 1:
                    return {"kind": "self", "class": holder.class_id, "attrs": attrs}
                return self._unresolved(base.SELF_ATTRIBUTE if attrs else base.UNKNOWN_RECEIVER, node)
            return self._unresolved(base.UNKNOWN_RECEIVER, node)
        # A variable. Its value is known only if it was assigned exactly once, from a call or a plain name.
        value = record.value
        if record.other or record.assignments != 1 or value is None:
            return self._unresolved(base.UNKNOWN_RECEIVER, node)
        if isinstance(value, ast.Call):
            literal = self._literal_getattr(value, holder, frozenset())
            origin = literal if literal is not None else self._resolve(value.func, holder, frozenset(), depth + 1)
            if origin["kind"] not in ("import", "local") or not attrs:
                return self._unresolved(base.CALL_RESULT if origin["kind"] in ("import", "local") else base.UNKNOWN_RECEIVER, node, origin)
            return {**origin, "attrs": [*origin.get("attrs", []), *attrs], "via": "instance"}
        if isinstance(value, (ast.Name, ast.Attribute)):
            origin = self._resolve(value, holder, frozenset(), depth + 1)
            if origin["kind"] not in ("import", "local"):
                return self._unresolved(base.UNKNOWN_RECEIVER, node, origin)
            return {**origin, "attrs": [*origin.get("attrs", []), *attrs], "via": origin.get("via") or "alias"}
        return self._unresolved(base.UNKNOWN_RECEIVER, node)

    def _literal_getattr(self, call: ast.Call, scope: _Scope, shadow: frozenset[str]) -> dict[str, Any] | None:
        """getattr(obj, "name") with a literal name is the same as obj.name."""
        if not (isinstance(call.func, ast.Name) and call.func.id == "getattr" and len(call.args) >= 2):
            return None
        if "getattr" in shadow or self._lookup(scope, "getattr")[0] is not None:
            return None
        name = call.args[1]
        if not (isinstance(name, ast.Constant) and isinstance(name.value, str) and name.value.isidentifier()):
            return None
        subject = self._resolve(call.args[0], scope, shadow, 1)
        if subject["kind"] not in ("import", "local"):
            return None
        return {**subject, "attrs": [*subject.get("attrs", []), name.value]}

    # -- usages ------------------------------------------------------------------------

    def _usage(self, scope: _Scope, node: ast.AST, usage: str, target: dict[str, Any]) -> None:
        if target["kind"] == "builtin" and usage != "call":
            return
        # A name with more than one possible import is recorded once per candidate; none of them is certain.
        candidates = [target]
        if target.get("alternatives"):
            shared = {k: v for k, v in target.items() if k != "alternatives"}
            candidates = [shared, *({**shared, **alternative} for alternative in target["alternatives"])]
        for candidate in candidates:
            if self._room():
                self.usages.append({
                    "caller": scope.symbol, "usage": usage, "line": getattr(node, "lineno", 0), "col": getattr(node, "col_offset", 0),
                    "end_line": getattr(node, "end_lineno", None), "text": self._text(node), "target": candidate,
                })

    def _call(self, scope: _Scope, node: ast.Call, shadow: frozenset[str], usage: str = "call") -> None:
        target = self._resolve(node.func, scope, shadow)
        if target["kind"] == "builtin" and not target["attrs"]:
            name = target["name"]
            if name == "getattr" and len(node.args) >= 2:
                literal = isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)
                if not literal:
                    target = self._unresolved(base.DYNAMIC_GETATTR, node, self._resolve(node.args[0], scope, shadow, 1))
            elif name in ("eval", "exec", "compile"):
                target = self._unresolved(base.DYNAMIC_EVAL, node)
            elif name == "__import__":
                target = self._dynamic_import(scope, node)
        elif target["kind"] == "import" and target["module"] == "importlib" and \
                ([target["name"], *target["attrs"]] in (["import_module"], [None, "import_module"])):
            target = self._dynamic_import(scope, node)
        self._usage(scope, node, usage, target)

    def _dynamic_import(self, scope: _Scope, node: ast.Call) -> dict[str, Any]:
        argument = node.args[0] if node.args else None
        if isinstance(argument, ast.Constant) and isinstance(argument.value, str) and argument.value and not argument.value.startswith("."):
            # A literal module name is as explicit as an import statement.
            self._import(scope, argument.value, None, None, 0, node, dynamic=True)
            return {"kind": "import", "module": argument.value, "name": None, "level": 0, "attrs": [], "via": "alias"}
        return self._unresolved(base.DYNAMIC_IMPORT, node)

    def _expressions(self, scope: _Scope, roots: list[ast.AST], shadow: frozenset[str] = frozenset()) -> None:
        """Record every call and every reference to an imported or local name inside the given expressions."""
        stack: list[tuple[ast.AST, frozenset[str], bool]] = [(root, shadow, False) for root in reversed(roots)]
        while stack:
            node, hidden, is_callee = stack.pop()
            self._tick()
            if isinstance(node, (*_FUNCTIONS, ast.ClassDef)):
                continue                                # inner scopes are analysed on their own
            if isinstance(node, ast.Lambda):
                arguments = node.args
                names = {a.arg for a in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)}
                names.update(a.arg for a in (arguments.vararg, arguments.kwarg) if a is not None)
                stack.extend((default, hidden, False) for default in (*arguments.defaults, *[d for d in arguments.kw_defaults if d is not None]))
                stack.append((node.body, hidden | names, False))
                continue
            if isinstance(node, _COMPREHENSIONS):
                names: set[str] = set()
                for generator in node.generators:
                    names.update(n.id for n in ast.walk(generator.target) if isinstance(n, ast.Name))
                inner = hidden | names
                for generator in node.generators:
                    stack.append((generator.iter, inner, False))
                    stack.extend((condition, inner, False) for condition in generator.ifs)
                parts = [node.key, node.value] if isinstance(node, ast.DictComp) else [node.elt]
                stack.extend((part, inner, False) for part in parts)
                continue
            if isinstance(node, ast.Call):
                self._call(scope, node, hidden)
                stack.append((node.func, hidden, True))
                stack.extend((argument, hidden, False) for argument in node.args)
                stack.extend((keyword.value, hidden, False) for keyword in node.keywords)
                continue
            if isinstance(node, (ast.Attribute, ast.Name)):
                if isinstance(getattr(node, "ctx", None), ast.Load) and not is_callee:
                    target = self._resolve(node, scope, hidden)
                    if target["kind"] in ("import", "local", "self"):
                        self._usage(scope, node, "reference", target)
                # Look inside the chain for calls (a.b().c), but do not record the chain's own prefixes again.
                inner_node: ast.AST = node
                while isinstance(inner_node, ast.Attribute):
                    inner_node = inner_node.value
                if not isinstance(inner_node, ast.Name):
                    stack.append((inner_node, hidden, True))
                continue
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.expr, ast.keyword, ast.comprehension, ast.arguments, ast.arg, ast.withitem,
                                      ast.match_case, ast.pattern, ast.stmt, ast.ExceptHandler)):
                    stack.append((child, hidden, False))

    # -- scopes ------------------------------------------------------------------------

    def _statement_expressions(self, node: ast.stmt) -> list[ast.AST]:
        """The expressions a statement evaluates in its own scope (not the bodies of nested blocks or scopes)."""
        if isinstance(node, _FUNCTIONS):
            arguments = node.args
            return [*node.decorator_list, *arguments.defaults, *[d for d in arguments.kw_defaults if d is not None]]
        if isinstance(node, ast.ClassDef):
            return [*node.decorator_list, *node.bases, *[k.value for k in node.keywords]]
        found: list[ast.AST] = []
        for name, value in ast.iter_fields(node):
            if name in ("body", "orelse", "finalbody", "handlers", "cases"):
                continue
            if isinstance(value, ast.AST):
                found.append(value)
            elif isinstance(value, list):
                found.extend(item for item in value if isinstance(item, ast.AST))
        return found

    def _header(self, scope: _Scope, node: ast.AST) -> None:
        """Record what a statement evaluates in `scope`. A bare decorator (@name) is recorded as a decorator use."""
        roots = self._statement_expressions(node)  # type: ignore[arg-type]
        bare: set[int] = set()
        for decorator in getattr(node, "decorator_list", []) if isinstance(node, (*_FUNCTIONS, ast.ClassDef)) else []:
            if not isinstance(decorator, ast.Call):
                bare.add(id(decorator))
                target = self._resolve(decorator, scope, frozenset())
                if target["kind"] in ("import", "local"):
                    self._usage(scope, decorator, "decorator", target)
        self._expressions(scope, [root for root in roots if id(root) not in bare] if bare else roots)

    def _process(self, scope: _Scope, body: list[ast.stmt], qualprefix: str, parent_symbol: str) -> None:
        pending: list[tuple[ast.AST, str]] = []
        for node in self._statements(body):
            self._header(scope, node)
            if isinstance(node, (*_FUNCTIONS, ast.ClassDef)):
                pending.append((node, qualprefix))
        for node, prefix in pending:
            if isinstance(node, ast.ClassDef):
                self._class(scope, node, prefix, parent_symbol)
            else:
                self._function(scope, node, prefix, parent_symbol, None)

    def _function(self, enclosing: _Scope, node: ast.FunctionDef | ast.AsyncFunctionDef, prefix: str, parent: str, class_id: str | None) -> None:
        qualname = f"{prefix}{node.name}"
        identity = self._symbol("method" if class_id else "function", qualname, node, parent)
        arguments = node.args
        positional = [*arguments.posonlyargs, *arguments.args]
        decorators = {_dotted(d.func if isinstance(d, ast.Call) else d) for d in node.decorator_list}
        self_name = positional[0].arg if class_id and positional and "staticmethod" not in decorators else None
        scope = _Scope("function", identity, enclosing, class_id if self_name else None, self_name)
        for argument in (*positional, *arguments.kwonlyargs, arguments.vararg, arguments.kwarg):
            if argument is not None:
                scope.name(argument.arg).param = True
        for parameter in getattr(node, "type_params", []):          # def f[T](...): T is a name of this scope
            if getattr(parameter, "name", None):
                scope.name(parameter.name).other = True
        self._collect(scope, node.body, f"{qualname}.<locals>.")
        self._process(scope, node.body, f"{qualname}.<locals>.", identity)

    def _class(self, enclosing: _Scope, node: ast.ClassDef, prefix: str, parent: str) -> None:
        qualname = f"{prefix}{node.name}"
        identity = self._symbol("class", qualname, node, parent)
        methods = self.class_methods.setdefault(identity, set())
        # The class body runs when the class is defined, in the enclosing code; names bound in the body are not
        # visible inside its methods, and uses of them in the body are not resolved.
        body_scope = _Scope(enclosing.kind, enclosing.symbol, enclosing)
        names: set[str] = {parameter.name for parameter in getattr(node, "type_params", []) if getattr(parameter, "name", None)}
        inner: list[ast.stmt] = []
        for statement in self._statements(node.body):
            if isinstance(statement, _FUNCTIONS):
                methods.add(statement.name)
                names.add(statement.name)
            elif isinstance(statement, ast.ClassDef):
                names.add(statement.name)
            else:
                for child in ast.walk(statement):
                    self._tick()
                    if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                        names.add(child.id)
                    elif isinstance(child, ast.alias):
                        names.add(child.asname or child.name.split(".", 1)[0])
                inner.append(statement)
        body_scope.class_names = frozenset(names)
        for statement in self._statements(node.body):
            if isinstance(statement, _FUNCTIONS):
                self._header(body_scope, statement)
                self._function(enclosing, statement, f"{qualname}.", identity, identity)
            elif isinstance(statement, ast.ClassDef):
                self._header(body_scope, statement)
                self._class(enclosing, statement, f"{qualname}.", identity)
            else:
                self._header(body_scope, statement)

    def _globals_rebound(self) -> set[str]:
        """Module-level names that a function declares `global` and then binds."""
        rebound: set[str] = set()
        stack: list[tuple[ast.AST, ast.AST | None]] = [(self.tree, None)]
        declared: dict[int, set[str]] = {}
        stored: dict[int, set[str]] = {}
        while stack:
            node, function = stack.pop()
            self._tick()
            if isinstance(node, _FUNCTIONS):
                function = node
            elif function is not None:
                if isinstance(node, ast.Global):
                    declared.setdefault(id(function), set()).update(node.names)
                elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
                    stored.setdefault(id(function), set()).add(node.id)
                elif isinstance(node, ast.alias):
                    stored.setdefault(id(function), set()).add(node.asname or node.name.split(".", 1)[0])
                elif isinstance(node, (*_FUNCTIONS, ast.ClassDef)):
                    stored.setdefault(id(function), set()).add(node.name)
            stack.extend((child, function) for child in ast.iter_child_nodes(node))
        for key, names in declared.items():
            rebound |= names & stored.get(key, set())
        return rebound

    def run(self) -> None:
        module_scope = _Scope("module", self.module, None)
        self._symbol("module", "", None, None)
        self._collect(module_scope, self.tree.body, "")
        for name in self._globals_rebound():
            module_scope.name(name).other = True          # some function assigns this module-level name at run time
        self._process(module_scope, self.tree.body, "", self.module)
        self.usages.sort(key=lambda usage: (usage["line"], usage["col"]))       # source order, whatever the traversal order was
        # A method used through self is known only if the class itself defines it. Reading any other
        # attribute of self (self.name) is ordinary data access and is not recorded.
        kept = []
        for usage in self.usages:
            target = usage["target"]
            if target["kind"] == "self":
                if target["attrs"][0] in self.class_methods.get(target["class"], ()):
                    usage["target"] = {"kind": "local", "symbol": f"{target['class']}.{target['attrs'][0]}", "attrs": [], "via": "self"}
                elif usage["usage"] == "reference":
                    continue
                else:
                    usage["target"] = {"kind": "unresolved", "reason": base.SELF_ATTRIBUTE,
                                       "expr": usage["text"][: self.limits.max_text]}
            kept.append(usage)
        self.usages = kept


class PythonAnalyzer(SourceAnalyzer):
    language = "python"
    extensions = (".py",)

    def module_name(self, path: str) -> str:
        stem = path[:-3] if path.endswith(".py") else path
        parts = stem.split("/")
        if parts[-1] == "__init__" and len(parts) > 1:
            parts = parts[:-1]
        return ".".join(parts)

    def parse(self, path: str, content: bytes, limits: SourceLimits) -> ParsedFile:
        result = ParsedFile(path=path, language=self.language, module=self.module_name(path))
        if b"\x00" in content:
            result.status, result.error = base.NOT_TEXT, "The file contains NUL bytes and is not text."
            return result
        try:
            # ast.parse only builds a syntax tree; given bytes it honours the file's encoding declaration.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")              # the file's own SyntaxWarnings are not ours to report
                tree = ast.parse(content, filename=posixpath.basename(path) or "<source>", mode="exec")
        except SyntaxError as exc:
            undecodable = isinstance(exc.__cause__, (UnicodeDecodeError, LookupError)) or "codec can't decode" in str(exc) \
                or "unknown encoding" in str(exc)
            result.status = base.NOT_TEXT if undecodable else base.SYNTAX_ERROR
            location = f" (line {exc.lineno})" if exc.lineno else ""
            result.error = (f"{exc.msg}{location}" if exc.msg else "invalid syntax")[:300]
            return result
        except (ValueError, UnicodeDecodeError, LookupError) as exc:
            result.status, result.error = base.NOT_TEXT, str(exc)[:300] or "The file is not text."
            return result
        except (RecursionError, MemoryError):
            result.status, result.error = base.TOO_COMPLEX, "The file is nested too deeply to parse."
            return result

        try:
            lines = content.decode("utf-8", "replace").splitlines()
            analysis = _FileAnalysis(path, result.module, tree, lines, limits)
            analysis.run()
        except _TooComplex:
            result.status, result.error = base.TOO_COMPLEX, f"The file has more than {limits.max_nodes} syntax nodes."
            return result
        except RecursionError:
            result.status, result.error = base.TOO_COMPLEX, "The file is nested too deeply to analyse."
            return result
        result.symbols, result.imports, result.usages = analysis.symbols, analysis.imports, analysis.usages
        result.nodes, result.truncated = analysis.nodes, analysis.truncated
        return result

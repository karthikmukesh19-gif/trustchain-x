"""The contract every language analyzer implements, and the records it produces.

Records are plain dictionaries so they can be stored and served unchanged:

symbol   {"id", "kind": module|class|function|method, "name", "qualname", "module", "path",
          "line", "end_line", "col", "parent", "decorators": [text], "bases": [text]}
import   {"scope": symbol id, "module": dotted name ("" for "from . import x"), "name": imported name or None,
          "bound": local name the import binds, "level": relative-import dots, "star": bool, "dynamic": bool,
          "line", "col", "statement": source text}
usage    {"caller": symbol id, "usage": call|reference|decorator, "line", "col", "end_line", "text": source text,
          "target": {...}}

A usage target is what the name being used was *statically bound to* in that file:

  {"kind": "import", "module", "name", "level", "attrs": [...]}   bound by an import statement
  {"kind": "local", "symbol": id, "attrs": [...]}                 a function or class defined in the same file
  {"kind": "self", "class": id, "attrs": [name]}                  a method called on self / cls
  {"kind": "builtin", "name"}                                     a Python builtin
  {"kind": "unresolved", "reason", "expr", "subject"?}            could not be bound statically

"via": "instance" marks an attribute taken from the *result of calling* the target (a method on an
instance, when the target is a class); "via": "alias" marks a name that was assigned from the target.
Both are inferences and lower the confidence of anything built on them.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

PARSED = "PARSED"
SYNTAX_ERROR = "SYNTAX_ERROR"          # not valid source for the analyzer's grammar
NOT_TEXT = "NOT_TEXT"                  # binary content or an undecodable encoding
TOO_COMPLEX = "TOO_COMPLEX"            # exceeded the node or nesting limit
PARSE_STATUSES = (PARSED, SYNTAX_ERROR, NOT_TEXT, TOO_COMPLEX)

# Reasons a use could not be bound statically.
UNKNOWN_RECEIVER = "UNKNOWN_RECEIVER"      # a parameter or variable whose value is not known statically
SELF_ATTRIBUTE = "SELF_ATTRIBUTE"          # self.x.y(...): the type of self.x is not known
CALL_RESULT = "CALL_RESULT"                # the callee is the result of another expression
UNDEFINED_NAME = "UNDEFINED_NAME"          # no binding for the name in the file
STAR_IMPORT = "STAR_IMPORT"                # the name may come from a "from x import *"
DYNAMIC_GETATTR = "DYNAMIC_GETATTR"        # getattr(obj, <non-literal>)
DYNAMIC_IMPORT = "DYNAMIC_IMPORT"          # __import__ / importlib.import_module with a non-literal name
DYNAMIC_EVAL = "DYNAMIC_EVAL"              # eval / exec / compile
DYNAMIC_REASONS = (DYNAMIC_GETATTR, DYNAMIC_IMPORT, DYNAMIC_EVAL, STAR_IMPORT)


@dataclass(frozen=True)
class SourceLimits:
    max_nodes: int = 200_000           # syntax-tree nodes visited per file
    max_records: int = 50_000          # symbols + imports + usages kept per file
    max_text: int = 200                # characters of source text kept per record


@dataclass
class ParsedFile:
    path: str
    language: str
    module: str
    status: str = PARSED
    error: str | None = None
    symbols: list[dict[str, Any]] = field(default_factory=list)
    imports: list[dict[str, Any]] = field(default_factory=list)
    usages: list[dict[str, Any]] = field(default_factory=list)
    nodes: int = 0
    truncated: bool = False            # the record limit was reached; what is kept is incomplete


class SourceAnalyzer(ABC):
    """Static analysis of one language. Implementations must never execute or import what they read."""

    language: str
    extensions: tuple[str, ...]

    @abstractmethod
    def module_name(self, path: str) -> str:
        """The stable module identity of a repository-relative path."""

    @abstractmethod
    def parse(self, path: str, content: bytes, limits: SourceLimits) -> ParsedFile:
        """Parse one file. Never raises for bad input: the outcome is in ParsedFile.status."""

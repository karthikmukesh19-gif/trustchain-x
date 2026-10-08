"""Source-code analysis: an inventory of source files and per-language static analyzers.

Nothing here executes, imports or installs repository code. Files are parsed as data.
"""

from __future__ import annotations

from app.analyzers.source.base import ParsedFile, SourceAnalyzer, SourceLimits
from app.analyzers.source.python_ast import PythonAnalyzer

# One analyzer per supported language. A new language is a new SourceAnalyzer registered here.
ANALYZERS: dict[str, SourceAnalyzer] = {analyzer.language: analyzer for analyzer in (PythonAnalyzer(),)}

__all__ = ["ANALYZERS", "ParsedFile", "SourceAnalyzer", "SourceLimits"]

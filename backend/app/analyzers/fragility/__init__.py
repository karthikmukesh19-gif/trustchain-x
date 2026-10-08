"""Dependency fragility: how exposed a project is to a problem in each of its dependencies.

Fragility is about structure and upkeep (who depends on a package, what it
brings in, how far behind its releases the project is). It is not
vulnerability severity and it predicts no specific event.
"""

from app.analyzers.fragility.fragility import MODEL_VERSION, DependencyFragilityAnalyzer

__all__ = ["MODEL_VERSION", "DependencyFragilityAnalyzer"]

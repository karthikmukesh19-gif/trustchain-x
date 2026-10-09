"""Evaluation support: the measures the research validation calls for, and an honest record of which have been measured.

Nothing in this package produces a result without data. A measure that has
no benchmark behind it is reported as NOT_EVALUATED.
"""

from app.evaluation.catalogue import NOT_EVALUATED, catalogue

__all__ = ["NOT_EVALUATED", "catalogue"]

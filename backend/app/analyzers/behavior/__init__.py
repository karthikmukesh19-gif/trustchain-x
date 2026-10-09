"""Commit behaviour analysis (model "commit-behaviour-v1").

Looks at what a commit changed, as text: which files, and which lines were
added or removed according to the diff GitHub publishes. Nothing from the
repository is checked out, imported or run.

The result is a set of behavioural indicators with evidence, and an anomaly
score that compares the commit with the repository's own earlier commits. An
anomaly is a departure from the usual pattern. It is not a finding of
wrongdoing: most anomalies are ordinary work that happens to be unusual.
"""

from app.analyzers.behavior.anomaly import MODEL_VERSION, assess
from app.analyzers.behavior.baseline import build_baseline
from app.analyzers.behavior.commit import analyse_commit
from app.analyzers.behavior.security_changes import INDICATOR_TYPES

__all__ = ["INDICATOR_TYPES", "MODEL_VERSION", "analyse_commit", "assess", "build_baseline"]

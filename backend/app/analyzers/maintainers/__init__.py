"""Maintainer behaviour intelligence (model "maintainer-behaviour-v1").

Describes how a repository is maintained, from public GitHub metadata: who
commits, how often, how releases are published, and where that pattern
changed. Every output is a behavioural indicator with its evidence.

None of it is a judgement about a person. An indicator says that a pattern
was observed; it never says, and cannot show, that anyone acted with bad
intent. Concentrated maintenance, bursts of work and quiet periods are all
normal in healthy projects.
"""

from app.analyzers.maintainers.anomaly import INDICATOR_TYPES, MODEL_VERSION
from app.analyzers.maintainers.profile import build_profile

__all__ = ["INDICATOR_TYPES", "MODEL_VERSION", "build_profile"]

"""Static attack-path simulation over stored evidence (model "attack-path-v1").

Nothing here contacts a repository, runs code or attempts an exploit. A path
is a chain of things that were observed (a dependency declaration, a graph
edge, an advisory match, a static reachability finding) plus clearly marked
derived steps. A path states what could be traversed if the advisory's
weakness were exploitable in this context, which is never established here.
"""

from app.analyzers.attack_paths.risk import MODEL_VERSION
from app.analyzers.attack_paths.simulation import Inputs, Limits, simulate

__all__ = ["MODEL_VERSION", "Inputs", "Limits", "simulate"]

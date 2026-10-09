"""Cross-layer security reasoning (model "cross-layer-reasoning-v1").

Correlates what the analysis layers stored into findings. The reasoning is a
fixed set of rules; every statement a finding makes points at the stored
records it rests on, and a finding that points at nothing is rejected before
it is saved. A language-model provider can be plugged in to phrase
explanations, but it is given only the evidence a finding already cites, and
whatever it returns is checked against that evidence before use.
"""

from app.ai.reasoning import CATEGORIES, MODEL_VERSION, SEVERITIES

__all__ = ["CATEGORIES", "MODEL_VERSION", "SEVERITIES"]

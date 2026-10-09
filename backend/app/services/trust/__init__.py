"""The TrustChain-X trust engine (model "trust-v1"): the layer that joins all the others into one explainable score."""

from app.services.trust.engine import compute
from app.services.trust.weights import MODEL_VERSION, WEIGHTS, WEIGHTS_STATEMENT

__all__ = ["MODEL_VERSION", "WEIGHTS", "WEIGHTS_STATEMENT", "compute"]

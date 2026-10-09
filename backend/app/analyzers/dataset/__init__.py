"""Self-validating security dataset (model "dataset-quality-v1").

The platform's analysis results for a snapshot are also a dataset: one record
per dependency, with features, labels and the provenance of every field. This
package measures how far that dataset can be relied on: whether records are
intact, complete, consistent, unique, balanced and traceable to their sources.

The checks find damage, gaps and contradictions. They cannot establish that
the underlying data is free of deliberate manipulation, and no result here
says that a dataset is "clean" or "poison-free".
"""

from app.analyzers.dataset.validation import MODEL_VERSION, STATUSES, validate

__all__ = ["MODEL_VERSION", "STATUSES", "validate"]

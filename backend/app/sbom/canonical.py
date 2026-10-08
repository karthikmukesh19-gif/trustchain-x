"""Canonical JSON and digests.

The canonical form is UTF-8 JSON with object keys sorted, no insignificant
whitespace and non-ASCII characters written literally (the approach of
RFC 8785; SBOM documents here contain strings, integers, booleans, lists and
objects only, so its number rules do not come into play). Lists keep their
order, so generators must emit lists in a deterministic order.

Two digests are kept for every SBOM:

document digest   over the whole canonical document; detects any change to
                  the stored bytes
content digest    over the document without its volatile fields (serial
                  number, generation timestamp, BOM version); equal for two
                  SBOMs generated from the same inventory at different times,
                  which is what makes regeneration comparable
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

ALGORITHM = "SHA-256"
DESCRIPTION = "UTF-8 JSON, object keys sorted, no insignificant whitespace (RFC 8785 style); SHA-256"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def content_view(document: dict[str, Any]) -> dict[str, Any]:
    """The document without the fields that legitimately differ between two generations of the same content."""
    view = copy.deepcopy(document)
    view.pop("serialNumber", None)
    view.pop("version", None)
    if isinstance(view.get("metadata"), dict):
        view["metadata"].pop("timestamp", None)
    return view


def content_digest(document: dict[str, Any]) -> str:
    return digest(content_view(document))

"""How evenly the labelled classes are represented."""

from __future__ import annotations

from collections import Counter
from typing import Any

BALANCED_MINORITY_SHARE = 0.2      # a minority class of at least this share is treated as balanced


def distribution(values: list[Any]) -> dict[str, int]:
    return {str(key): count for key, count in sorted(Counter("unknown" if value is None else value for value in values).items(), key=lambda kv: str(kv[0]))}


def evaluate(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Class balance of the `vulnerable` label, with the other distributions for context.

    A dataset holding one class only cannot be used to tell the classes apart;
    that is reported as a value of 0 with an explanation. When the label is
    unknown for every record (no vulnerability check), balance is unknown.
    """
    labels = [(record.get("labels") or {}).get("vulnerable") for record in records]
    known = [value for value in labels if isinstance(value, bool)]
    positives = sum(known)
    result: dict[str, Any] = {
        "label": "vulnerable", "records": len(records), "labelled": len(known), "unlabelled": len(labels) - len(known),
        "classes": {"true": positives, "false": len(known) - positives},
        "distributions": {
            "ecosystem": distribution([(record.get("identity") or {}).get("ecosystem") for record in records]),
            "relationship": distribution([(record.get("features") or {}).get("relationship") for record in records]),
            "risk_level": distribution([(record.get("labels") or {}).get("risk_level") for record in records]),
            "reachability_state": distribution([(record.get("features") or {}).get("reachability_state") for record in records]),
        },
    }
    if not known:
        return {**result, "minority_share": None, "value": None, "note": "The label is unknown for every record: no vulnerability check covers this snapshot."}
    minority = min(positives, len(known) - positives) / len(known)
    note = None
    if minority == 0:
        note = f"Every labelled record has the same class ({'vulnerable' if positives else 'not vulnerable'}). One class alone cannot be compared with another."
    elif minority < BALANCED_MINORITY_SHARE:
        note = f"The smaller class is {minority:.1%} of the labelled records. That is typical of dependency data and limits what can be learned about it."
    return {**result, "minority_share": round(minority, 4), "value": round(min(1.0, minority / BALANCED_MINORITY_SHARE), 4), "note": note}

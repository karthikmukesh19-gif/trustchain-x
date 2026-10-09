"""Evaluation measures, as plain functions over labelled data.

Every function returns None when the measure is undefined for the input (for
example recall with no positive case) instead of a made-up number. None of
them is called by the platform on its own: they need ground truth, which
only a benchmark supplies.
"""

from __future__ import annotations

import math
import time
from typing import Any, Callable, Sequence


def confusion(predicted: Sequence[bool], actual: Sequence[bool]) -> dict[str, int]:
    if len(predicted) != len(actual):
        raise ValueError("predicted and actual must have the same length")
    counts = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for guess, truth in zip(predicted, actual):
        counts["tp" if guess and truth else "fp" if guess else "fn" if truth else "tn"] += 1
    return counts


def _ratio(numerator: float, denominator: float) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def classification(predicted: Sequence[bool], actual: Sequence[bool]) -> dict[str, Any]:
    """Precision, recall, false-positive rate, false-negative rate, F1 and accuracy, with the counts they come from."""
    c = confusion(predicted, actual)
    precision, recall = _ratio(c["tp"], c["tp"] + c["fp"]), _ratio(c["tp"], c["tp"] + c["fn"])
    f1 = round(2 * precision * recall / (precision + recall), 4) if precision and recall else (0.0 if precision == 0 or recall == 0 else None)
    return {**c, "n": len(predicted), "precision": precision, "recall": recall, "false_positive_rate": _ratio(c["fp"], c["fp"] + c["tn"]),
            "false_negative_rate": _ratio(c["fn"], c["fn"] + c["tp"]), "f1": f1, "accuracy": _ratio(c["tp"] + c["tn"], len(predicted))}


def coverage(decided: int, total: int) -> float | None:
    """Share of cases for which the component gave a definite answer (not unknown or unsupported)."""
    return _ratio(decided, total)


def precision_at_k(ranked_relevance: Sequence[bool], k: int) -> float | None:
    """Of the k highest-ranked items, the share that are relevant."""
    if k <= 0 or not ranked_relevance:
        return None
    top = ranked_relevance[:k]
    return round(sum(top) / len(top), 4)


def ndcg(ranked_gains: Sequence[float], k: int | None = None) -> float | None:
    """Normalised discounted cumulative gain of a ranking, where each item's gain is its true relevance."""
    gains = list(ranked_gains[:k] if k else ranked_gains)
    ideal = sorted(ranked_gains, reverse=True)[:len(gains)]
    dcg = sum(gain / math.log2(position + 2) for position, gain in enumerate(gains))
    best = sum(gain / math.log2(position + 2) for position, gain in enumerate(ideal))
    return round(dcg / best, 4) if best > 0 else None


def _ranks(values: Sequence[float]) -> list[float]:
    order = sorted(range(len(values)), key=lambda index: values[index])
    ranks = [0.0] * len(values)
    position = 0
    while position < len(order):
        end = position
        while end + 1 < len(order) and values[order[end + 1]] == values[order[position]]:
            end += 1
        for index in order[position:end + 1]:
            ranks[index] = (position + end) / 2 + 1          # tied values share the mean of their ranks
        position = end + 1
    return ranks


def spearman(first: Sequence[float], second: Sequence[float]) -> float | None:
    """Spearman rank correlation, for comparing predicted scores with later-observed outcomes."""
    if len(first) != len(second):
        raise ValueError("both sequences must have the same length")
    if len(first) < 3:
        return None
    a, b = _ranks(first), _ranks(second)
    mean_a, mean_b = sum(a) / len(a), sum(b) / len(b)
    covariance = sum((x - mean_a) * (y - mean_b) for x, y in zip(a, b))
    spread = math.sqrt(sum((x - mean_a) ** 2 for x in a) * sum((y - mean_b) ** 2 for y in b))
    return round(covariance / spread, 4) if spread else None


def brier(probabilities: Sequence[float], outcomes: Sequence[bool]) -> float | None:
    """Mean squared difference between stated probabilities and what happened. Lower is better."""
    if len(probabilities) != len(outcomes):
        raise ValueError("probabilities and outcomes must have the same length")
    if not probabilities:
        return None
    return round(sum((p - (1.0 if outcome else 0.0)) ** 2 for p, outcome in zip(probabilities, outcomes)) / len(probabilities), 4)


def expected_calibration_error(confidences: Sequence[float], correct: Sequence[bool], bins: int = 10) -> dict[str, Any] | None:
    """How far stated confidence is from observed accuracy, averaged over confidence bins weighted by their size."""
    if len(confidences) != len(correct):
        raise ValueError("confidences and correct must have the same length")
    if not confidences:
        return None
    grouped: list[list[tuple[float, bool]]] = [[] for _ in range(bins)]
    for value, right in zip(confidences, correct):
        grouped[min(bins - 1, max(0, int(value * bins)))].append((value, right))
    rows, error = [], 0.0
    for index, members in enumerate(grouped):
        if not members:
            continue
        mean_confidence = sum(value for value, _right in members) / len(members)
        accuracy = sum(right for _value, right in members) / len(members)
        error += len(members) / len(confidences) * abs(mean_confidence - accuracy)
        rows.append({"bin": f"{index / bins:.1f}-{(index + 1) / bins:.1f}", "n": len(members), "mean_confidence": round(mean_confidence, 4),
                     "accuracy": round(accuracy, 4)})
    return {"ece": round(error, 4), "bins": rows, "n": len(confidences)}


def timed(function: Callable[[], Any], repeats: int = 3) -> dict[str, Any]:
    """Wall-clock time of a call: the best and the mean of `repeats` runs, in seconds. A measurement of this machine."""
    durations = []
    result = None
    for _ in range(max(1, repeats)):
        started = time.perf_counter()
        result = function()
        durations.append(time.perf_counter() - started)
    return {"best_seconds": round(min(durations), 6), "mean_seconds": round(sum(durations) / len(durations), 6), "repeats": len(durations),
            "result": result}


def scalability(run: Callable[[int], Any], sizes: Sequence[int], repeats: int = 1) -> list[dict[str, Any]]:
    """Time `run(size)` for each size, to see how processing time grows with input size."""
    points = []
    for size in sizes:
        measured = timed(lambda size=size: run(size), repeats)
        points.append({"size": size, "best_seconds": measured["best_seconds"], "mean_seconds": measured["mean_seconds"]})
    return points

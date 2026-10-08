"""Concentration: how much of a project rests on one package.

Two views, both observed:
  graph   the share of the project's packages that depend on it, and the share of the
          project's direct dependencies that lead to it
  source  when a code reachability analysis exists, the share of the application's
          modules that import it
"""

from __future__ import annotations

from typing import Any


def dependency_concentration(row: dict[str, Any], usage: dict[str, Any] | None, modules: int | None) -> dict[str, Any]:
    importing = (usage or {}).get("importing_modules")
    return {
        "dependents": row["dependents"], "dependents_share": row["dependents_share"],
        "reached_by_direct": row["reached_by_direct"], "reached_by_direct_share": row["reached_by_direct_share"],
        "importing_modules": importing,
        "importing_module_share": round(importing / modules, 4) if importing is not None and modules else None,
        "use_sites": (usage or {}).get("use_sites"),
    }


def single_point(row: dict[str, Any]) -> bool:
    """Most of the project's direct dependencies converge on this package, which the project does not control directly."""
    share = row["reached_by_direct_share"]
    return not row["direct"] and row["reached_by_direct"] >= 3 and share is not None and share >= 0.5

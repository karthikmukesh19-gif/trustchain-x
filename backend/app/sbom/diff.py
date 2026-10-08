"""Compare two SBOM documents.

A component's identity is its ecosystem and normalised name; its versions are
compared as a set, because one package can be present in several versions
(common in npm trees).

ADDED     the package is in the target only
REMOVED   the package is in the base only
CHANGED   the package is in both and its versions differ, or the versions are
          the same but recorded metadata (name, scope, hashes, PURL,
          relationship, other properties) differs

Differences outside the component list - the repository and commit the SBOM
describes, the generator, the snapshot properties - are reported as
`document_changes`. Two SBOMs of different snapshots always differ there.

"Ecosystem change" - a name that disappears from one ecosystem and appears in
another - is reported separately and labelled INFERRED: equal names in
different ecosystems are not necessarily the same software.
"""

from __future__ import annotations

from typing import Any

from app.sbom.canonical import digest
from app.sbom.cyclonedx import component_property, relationships

ADDED, REMOVED, CHANGED = "ADDED", "REMOVED", "CHANGED"
MAX_ITEMS = 5000
MAX_RELATIONSHIPS = 1000
_COMPARED_FIELDS = ("type", "group", "name", "scope", "purl", "hashes")
_DOCUMENT_FIELDS = ("bomFormat", "specVersion", "compositions")


def _index(document: dict[str, Any]) -> dict[tuple[str, str], dict[str, dict[str, Any]]]:
    index: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
    components = document.get("components")
    for item in components if isinstance(components, list) else []:
        if not isinstance(item, dict):
            continue
        ecosystem = component_property(item, "ecosystem") or "unknown"
        name = component_property(item, "normalized_name") or item.get("name", "")
        index.setdefault((ecosystem, name), {})[item.get("version") or ""] = item
    return index


def _properties(component: dict[str, Any]) -> dict[str, Any]:
    properties = component.get("properties")
    return {p["name"]: p.get("value") for p in properties if isinstance(p, dict) and isinstance(p.get("name"), str)} \
        if isinstance(properties, list) else {}


def _field_changes(old: dict[str, Any], new: dict[str, Any]) -> list[dict[str, Any]]:
    changes = []
    for name in _COMPARED_FIELDS:
        if old.get(name) != new.get(name):
            changes.append({"field": name, "old": old.get(name), "new": new.get(name)})
    old_properties, new_properties = _properties(old), _properties(new)
    for name in sorted(set(old_properties) | set(new_properties)):
        if old_properties.get(name) != new_properties.get(name):
            changes.append({"field": name.removeprefix("trustchain:"), "old": old_properties.get(name), "new": new_properties.get(name)})
    return changes


def _document_changes(base: dict[str, Any], target: dict[str, Any]) -> list[dict[str, Any]]:
    """Differences outside the component list: what the SBOM says it describes and how it was produced.

    The generation timestamp, serial number and BOM version are expected to differ and are not reported.
    """
    changes = []
    for name in _DOCUMENT_FIELDS:
        if base.get(name) != target.get(name):
            changes.append({"field": name, "old": base.get(name), "new": target.get(name)})
    old_meta = base.get("metadata") if isinstance(base.get("metadata"), dict) else {}
    new_meta = target.get("metadata") if isinstance(target.get("metadata"), dict) else {}
    for name in ("component", "tools"):
        if old_meta.get(name) != new_meta.get(name):
            changes.append({"field": f"metadata.{name}", "old": old_meta.get(name), "new": new_meta.get(name)})
    old_properties = {p.get("name"): p.get("value") for p in old_meta.get("properties", []) or [] if isinstance(p, dict)}
    new_properties = {p.get("name"): p.get("value") for p in new_meta.get("properties", []) or [] if isinstance(p, dict)}
    for name in sorted(set(old_properties) | set(new_properties), key=str):
        if old_properties.get(name) != new_properties.get(name):
            changes.append({"field": f"metadata.{str(name).removeprefix('trustchain:')}",
                            "old": old_properties.get(name), "new": new_properties.get(name)})
    return changes


def compare(base: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    """Differences going from `base` to `target`."""
    before, after = _index(base), _index(target)
    items: list[dict[str, Any]] = []
    for key in sorted(set(before) | set(after)):
        ecosystem, name = key
        old, new = before.get(key, {}), after.get(key, {})
        old_versions, new_versions = sorted(old), sorted(new)
        entry: dict[str, Any] = {"ecosystem": ecosystem, "name": name,
                                 "old_versions": [v or None for v in old_versions], "new_versions": [v or None for v in new_versions]}
        if not old:
            entry["change"] = ADDED
        elif not new:
            entry["change"] = REMOVED
        elif old_versions != new_versions:
            entry["change"] = CHANGED
            entry["change_type"] = "version"
            if len(old_versions) == 1 and len(new_versions) == 1:
                entry["old_version"], entry["new_version"] = old_versions[0] or None, new_versions[0] or None
        else:
            fields: list[dict[str, Any]] = []
            for version in old_versions:
                if digest(old[version]) != digest(new[version]):
                    fields.extend({**change, "version": version or None} for change in _field_changes(old[version], new[version]))
            if not fields:
                continue
            entry["change"] = CHANGED
            entry["change_type"] = "metadata"
            entry["fields"] = fields[:50]
        items.append(entry)

    removed_names = {(i["name"], i["ecosystem"]) for i in items if i["change"] == REMOVED}
    ecosystem_changes = []
    for item in items:
        if item["change"] == ADDED:
            for name, ecosystem in sorted(removed_names):
                if name == item["name"] and ecosystem != item["ecosystem"]:
                    ecosystem_changes.append({"name": name, "old_ecosystem": ecosystem, "new_ecosystem": item["ecosystem"],
                                              "basis": "INFERRED",
                                              "reason": "The same package name was removed from one ecosystem and added in another."})

    document_changes = _document_changes(base, target)
    old_edges, new_edges = relationships(base), relationships(target)
    added_edges, removed_edges = sorted(new_edges - old_edges), sorted(old_edges - new_edges)
    summary = {
        "added": sum(1 for i in items if i["change"] == ADDED),
        "removed": sum(1 for i in items if i["change"] == REMOVED),
        "changed": sum(1 for i in items if i["change"] == CHANGED),
        "version_changes": sum(1 for i in items if i.get("change_type") == "version"),
        "metadata_changes": sum(1 for i in items if i.get("change_type") == "metadata"),
        "ecosystem_changes": len(ecosystem_changes),
        "relationships_added": len(added_edges), "relationships_removed": len(removed_edges),
        "components_before": sum(len(v) for v in before.values()), "components_after": sum(len(v) for v in after.values()),
        "document_changes": len(document_changes),
        "identical": not items and not added_edges and not removed_edges and not document_changes,
    }
    return {
        "summary": summary,
        "items": items[:MAX_ITEMS], "items_truncated": len(items) > MAX_ITEMS,
        "ecosystem_changes": ecosystem_changes[:200],
        "document_changes": document_changes,
        "relationships_added": [{"from": a, "to": b} for a, b in added_edges[:MAX_RELATIONSHIPS]],
        "relationships_removed": [{"from": a, "to": b} for a, b in removed_edges[:MAX_RELATIONSHIPS]],
        "relationships_truncated": len(added_edges) > MAX_RELATIONSHIPS or len(removed_edges) > MAX_RELATIONSHIPS,
    }

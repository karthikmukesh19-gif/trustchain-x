"""CycloneDX 1.5 JSON generation from a snapshot's dependency inventory.

Only what the repository evidence establishes is written. In particular:

* `version` is omitted for a dependency whose version is unresolved
* `hashes` are written only for digests recorded in a lockfile, converted
  from base64 to hex where needed (the same digest, re-encoded); a recorded
  digest that is not a recognised file hash (for example Go's `h1:` module
  hash) is kept as a property rather than presented as a file hash
* no licences are written: the inventory does not contain licence data
* `scope` is written only when the dependency files establish it

Output order is deterministic: components and dependency lists are sorted,
so the same inventory always yields the same content digest.
"""

from __future__ import annotations

import base64
import binascii
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from app.sbom.canonical import content_digest

FORMAT = "CycloneDX"
SPEC_VERSION = "1.5"
MEDIA_TYPE = "application/vnd.cyclonedx+json"
GENERATOR_NAME = "TrustChain-X"
GENERATOR_VERSION = "3.0.0"
ROOT_REF = "root"

_HASH_ALGORITHMS = {"md5": ("MD5", 32), "sha1": ("SHA-1", 40), "sha256": ("SHA-256", 64), "sha384": ("SHA-384", 96), "sha512": ("SHA-512", 128)}
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_NAMESPACE = uuid.UUID("6f1f6f0e-7d5b-5f0b-9a57-2c1f3c1d9b7e")
_RUNTIME_SCOPES = {"runtime", "peer"}
_NON_RUNTIME_SCOPES = {"dev", "test", "build"}


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return None


def _property(name: str, value: Any) -> dict[str, str] | None:
    if value is None or value == "" or value == []:
        return None
    if isinstance(value, bool):
        value = "true" if value else "false"
    elif isinstance(value, (list, tuple)):
        value = ", ".join(str(v) for v in value)
    return {"name": f"trustchain:{name}", "value": str(value)}


def _properties(pairs: list[tuple[str, Any]]) -> list[dict[str, str]]:
    return sorted((p for p in (_property(n, v) for n, v in pairs) if p), key=lambda p: p["name"])


def convert_hash(algorithm: Any, value: Any) -> dict[str, str] | None:
    """A lockfile digest as a CycloneDX hash, or None if it is not a recognised file hash."""
    if not isinstance(algorithm, str) or not isinstance(value, str):
        return None
    known = _HASH_ALGORITHMS.get(algorithm.lower().replace("-", ""))
    if known is None:
        return None
    name, hex_length = known
    value = value.strip()
    if len(value) == hex_length and _HEX.match(value):
        return {"alg": name, "content": value.lower()}
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    return {"alg": name, "content": decoded.hex()} if len(decoded) * 2 == hex_length else None


def _scope(dependency: dict[str, Any]) -> str | None:
    scopes = {s for s in dependency.get("scopes", []) if s != "unknown"}
    if dependency.get("optional") is True or scopes == {"optional"}:
        return "optional"
    if scopes & _RUNTIME_SCOPES:
        return "required"
    if scopes and scopes <= _NON_RUNTIME_SCOPES:
        return "excluded"     # development, test or build only: not part of the runtime
    return None


def _split_name(ecosystem: str, name: str) -> tuple[str | None, str]:
    if ecosystem == "maven" and ":" in name:
        group, artifact = name.split(":", 1)
        return group, artifact
    if ecosystem == "npm" and name.startswith("@") and "/" in name:
        group, package = name.split("/", 1)
        return group, package
    return None, name


def component(dependency: dict[str, Any]) -> dict[str, Any]:
    group, name = _split_name(dependency["ecosystem"], dependency["name"])
    item: dict[str, Any] = {"type": "library", "bom-ref": dependency["node_id"], "name": name}
    if group:
        item["group"] = group
    if dependency.get("version"):
        item["version"] = dependency["version"]
    if dependency.get("purl"):
        item["purl"] = dependency["purl"]
    scope = _scope(dependency)
    if scope:
        item["scope"] = scope

    hashes, other_integrity = [], []
    for entry in dependency.get("integrity", []) or []:
        converted = convert_hash(entry.get("algorithm"), entry.get("value"))
        if converted and converted not in hashes:
            hashes.append(converted)
        elif not converted and entry.get("algorithm") and entry.get("value"):
            other_integrity.append(f"{entry['algorithm']}:{entry['value']}")
    if hashes:
        item["hashes"] = sorted(hashes, key=lambda h: (h["alg"], h["content"]))

    files = sorted({e["source_file"] for e in dependency.get("evidence", []) if e.get("source_file")})
    item["properties"] = _properties([
        ("ecosystem", dependency["ecosystem"]),
        ("normalized_name", dependency.get("normalized_name")),
        ("version_status", dependency.get("version_status")),
        ("version_basis", dependency.get("version_basis")),
        ("constraints", dependency.get("constraints")),
        ("relationship", dependency.get("relationship")),
        ("relationship_basis", dependency.get("relationship_basis")),
        ("depth", dependency.get("depth")),
        ("scopes", sorted(dependency.get("scopes", []))),
        ("package_managers", sorted(dependency.get("package_managers", []))),
        ("source_files", files[:20]),
        ("recorded_integrity", sorted(other_integrity)),
    ])
    return item


def build(*, project_id: str, snapshot: dict[str, Any], dependencies: list[dict[str, Any]], edges: list[dict[str, Any]],
          generated_at: datetime, generator_version: str = GENERATOR_VERSION) -> dict[str, Any]:
    """Build the CycloneDX document for one snapshot."""
    components = sorted((component(d) for d in dependencies), key=lambda c: c["bom-ref"])
    refs = {c["bom-ref"] for c in components} | {ROOT_REF}
    depends: dict[str, set[str]] = {ref: set() for ref in refs}
    for edge in edges:
        if edge.get("source") in refs and edge.get("target") in refs and edge["source"] != edge["target"]:
            depends[edge["source"]].add(edge["target"])

    files = snapshot.get("dependency_files", []) or []
    not_parsed = [f.get("path") for f in files if f.get("status") != "PARSED"]
    unresolved = sum(1 for d in dependencies if not d.get("version"))
    document: dict[str, Any] = {
        "bomFormat": FORMAT,
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": _iso(generated_at),
            "tools": {"components": [{"type": "application", "name": GENERATOR_NAME, "version": generator_version}]},
            "component": {
                "type": "application", "bom-ref": ROOT_REF, "name": snapshot["repository_full_name"],
                "version": snapshot["commit_sha"],
                "externalReferences": [{"type": "vcs", "url": snapshot["repository_url"]}],
            },
            "properties": _properties([
                ("project_id", project_id),
                ("snapshot_id", str(snapshot["_id"])),
                ("commit_sha", snapshot["commit_sha"]),
                ("tree_sha", snapshot.get("tree_sha")),
                ("branch", snapshot.get("branch")),
                ("snapshot_collected_at", _iso(snapshot.get("collected_at"))),
                ("analyzer_version", snapshot.get("analyzer_version")),
                ("collection_method", snapshot.get("collection_method")),
                ("dependency_files", len(files)),
                ("dependency_files_not_parsed", sorted(p for p in not_parsed if p)[:50]),
                ("unresolved_versions", unresolved),
            ]),
        },
        "components": components,
        "dependencies": [{"ref": ref, "dependsOn": sorted(depends[ref])} for ref in sorted(refs)],
        # Completeness cannot be proven from repository files alone; it is stated as such rather than assumed.
        "compositions": [{"aggregate": "incomplete" if not_parsed or unresolved else "unknown", "assemblies": [ROOT_REF]}],
    }
    serial = uuid.uuid5(_NAMESPACE, f"{project_id}:{snapshot['_id']}:{content_digest(document)}")
    document["serialNumber"] = f"urn:uuid:{serial}"
    return document


def relationships(document: dict[str, Any]) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    entries = document.get("dependencies")
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, dict) and isinstance(entry.get("ref"), str):
            targets = entry.get("dependsOn")
            for target in targets if isinstance(targets, list) else []:
                if isinstance(target, str):
                    pairs.add((entry["ref"], target))
    return pairs


def component_property(item: dict[str, Any], name: str) -> str | None:
    properties = item.get("properties")
    for entry in properties if isinstance(properties, list) else []:
        if isinstance(entry, dict) and entry.get("name") == f"trustchain:{name}":
            value = entry.get("value")
            return value if isinstance(value, str) else None
    return None

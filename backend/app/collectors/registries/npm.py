"""npm registry: GET /{name}. The full document carries release dates; the compact form
(Accept: application/vnd.npm.install-v1+json) is far smaller and carries the version list only."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from app.collectors.registries.base import COLLECTED, COMPACT, ERROR, FULL, INVALID_NAME, MAX_VERSIONS, NOT_FOUND, PackageRegistry, RegistryError, newest, parse_time

# New npm names are lowercase, but the registry still holds older mixed-case names ("JSONStream") as packages of
# their own, distinct from the lowercase spelling. The name is therefore sent exactly as the repository gives it.
_NAME = re.compile(r"(@[a-z0-9~-][a-z0-9._~-]{0,100}/)?[A-Za-z0-9~-][A-Za-z0-9._~-]{0,200}")
COMPACT_TYPE = "application/vnd.npm.install-v1+json"


class NpmRegistry(PackageRegistry):
    name = "npm"
    ecosystem = "npm"
    display_name = "npm registry"

    def valid_name(self, normalized_name: str) -> bool:
        return isinstance(normalized_name, str) and len(normalized_name) <= 214 and _NAME.fullmatch(normalized_name) is not None

    def lookup_name(self, dependency: dict[str, Any]) -> str:
        return dependency.get("name") or dependency["normalized_name"]

    def lookup(self, normalized_name: str, detail: str = FULL) -> dict[str, Any]:
        if not self.valid_name(normalized_name):
            return self.result(normalized_name, INVALID_NAME, error_code=INVALID_NAME)
        path = "/" + quote(normalized_name, safe="@")              # "@scope/name" -> "@scope%2Fname"
        url = f"{self.base_url}{path}"
        try:
            body = self.get_json(path, accept="application/json" if detail == FULL else COMPACT_TYPE)
        except RegistryError as exc:
            return self.result(normalized_name, NOT_FOUND if exc.code == NOT_FOUND else ERROR, error_code=exc.code, source_url=url)
        published = body.get("versions") if isinstance(body, dict) else None
        tags = body.get("dist-tags") if isinstance(body, dict) else None
        if not isinstance(published, dict) or not isinstance(tags, dict):
            return self.result(normalized_name, ERROR, error_code="BAD_RESPONSE", source_url=url)
        times = body.get("time") if isinstance(body.get("time"), dict) else {}
        versions: dict[str, Any] = {}
        deprecated: list[str] = []
        latest = tags.get("latest") if isinstance(tags.get("latest"), str) and len(tags["latest"]) <= 100 else None
        for version, manifest in newest(list(published.items()), latest, MAX_VERSIONS):
            if not isinstance(version, str) or len(version) > 100:
                continue
            versions[version] = parse_time(times.get(version)) if detail == FULL else None
            if isinstance(manifest, dict) and manifest.get("deprecated"):
                deprecated.append(version)
        # A deprecated npm version is still published and installable; it is not a withdrawn one.
        return self.result(
            normalized_name, COLLECTED, detail=FULL if detail == FULL else COMPACT, latest_version=latest,
            latest_published_at=versions.get(latest) if latest else None, versions=versions,
            versions_truncated=len(published) > len(versions), deprecated_versions=sorted(deprecated)[:500],
            deprecated=(latest in deprecated) if latest else None, source_url=url)

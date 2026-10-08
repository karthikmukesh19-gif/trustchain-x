"""PyPI JSON API: GET /pypi/{name}/json."""

from __future__ import annotations

import re
from typing import Any

from app.collectors.registries.base import COLLECTED, ERROR, FULL, INVALID_NAME, MAX_VERSIONS, NOT_FOUND, PackageRegistry, RegistryError, newest, parse_time

_NAME = re.compile(r"[a-z0-9]([a-z0-9._-]{0,198}[a-z0-9])?")


class PyPIRegistry(PackageRegistry):
    name = "pypi"
    ecosystem = "pypi"
    display_name = "PyPI"

    def valid_name(self, normalized_name: str) -> bool:
        return isinstance(normalized_name, str) and _NAME.fullmatch(normalized_name) is not None

    def lookup(self, normalized_name: str, detail: str = FULL) -> dict[str, Any]:
        if not self.valid_name(normalized_name):
            return self.result(normalized_name, INVALID_NAME, error_code=INVALID_NAME)
        url = f"{self.base_url}/pypi/{normalized_name}/json"
        try:
            body = self.get_json(f"/pypi/{normalized_name}/json")
        except RegistryError as exc:
            return self.result(normalized_name, NOT_FOUND if exc.code == NOT_FOUND else ERROR, error_code=exc.code, source_url=url)
        info = body.get("info") if isinstance(body, dict) else None
        releases = body.get("releases") if isinstance(body, dict) else None
        if not isinstance(info, dict) or not isinstance(releases, dict):
            return self.result(normalized_name, ERROR, error_code="BAD_RESPONSE", source_url=url)
        versions: dict[str, Any] = {}
        withdrawn: list[str] = []
        latest = info.get("version") if isinstance(info.get("version"), str) and len(info["version"]) <= 100 else None
        for version, files in newest(list(releases.items()), latest, MAX_VERSIONS):
            if not isinstance(version, str) or len(version) > 100:
                continue
            files = [f for f in files if isinstance(f, dict)] if isinstance(files, list) else []
            times = [t for t in (parse_time(f.get("upload_time_iso_8601")) for f in files) if t is not None]
            versions[version] = min(times) if times else None          # the first file of a release marks its publication
            if files and all(f.get("yanked") is True for f in files):
                withdrawn.append(version)
        return self.result(
            normalized_name, COLLECTED, detail=FULL, latest_version=latest, latest_published_at=versions.get(latest) if latest else None,
            versions=versions, versions_truncated=len(releases) > len(versions), withdrawn_versions=sorted(withdrawn)[:500],
            deprecated=None, source_url=url)

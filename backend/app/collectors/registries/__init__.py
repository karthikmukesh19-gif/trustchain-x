"""Package registry clients, keyed by the ecosystem they serve."""

from __future__ import annotations

import httpx

from app.collectors.registries.base import PackageRegistry
from app.collectors.registries.npm import NpmRegistry
from app.collectors.registries.pypi import PyPIRegistry
from app.config.settings import Settings

__all__ = ["PackageRegistry", "build_registries"]


def build_registries(settings: Settings, transport: httpx.BaseTransport | None = None) -> dict[str, PackageRegistry]:
    """The registries enabled in configuration, keyed by ecosystem. A new registry is a subclass and one line here."""
    registries: dict[str, PackageRegistry] = {}
    if "pypi" in settings.package_metadata_providers:
        registries["pypi"] = PyPIRegistry(settings, settings.pypi_api_url, transport)
    if "npm" in settings.package_metadata_providers:
        registries["npm"] = NpmRegistry(settings, settings.npm_registry_url, transport)
    return registries

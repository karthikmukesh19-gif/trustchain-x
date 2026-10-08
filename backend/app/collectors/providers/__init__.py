"""Vulnerability intelligence providers."""

from __future__ import annotations

import httpx

from app.collectors.providers.base import ProviderError, VulnerabilityProvider
from app.collectors.providers.osv import OsvProvider
from app.config.settings import Settings

__all__ = ["ProviderError", "VulnerabilityProvider", "build_providers"]


def build_providers(settings: Settings, transport: httpx.BaseTransport | None = None) -> dict[str, VulnerabilityProvider]:
    """Instantiate the providers enabled in configuration, keyed by name.

    Adding a source means adding a VulnerabilityProvider subclass and one line
    here; synchronisation, storage and matching work on the normalised form
    and do not change.
    """
    providers: dict[str, VulnerabilityProvider] = {}
    if "osv" in settings.vulnerability_providers:
        providers["osv"] = OsvProvider(settings, transport=transport)
    return providers

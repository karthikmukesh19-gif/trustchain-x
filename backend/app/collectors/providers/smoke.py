"""LIVE PROVIDER VALIDATION - a manual check against the real vulnerability provider.

This is not part of the automated test suite (which never uses the network).
It contacts the configured provider, asks about one package version, fetches
and normalises what the provider reports, and runs the local version matching
on each record, printing every step. Nothing is written to the database.

    python -m app.collectors.providers.smoke pypi requests 2.19.1
    docker compose exec backend python -m app.collectors.providers.smoke npm lodash 4.17.20

Exit status: 0 if the provider answered and every reported record could be
fetched and normalised; 1 otherwise.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any, Callable

from app.analyzers.normalize import normalize_name
from app.analyzers.vulnerabilities import matching
from app.collectors.providers import build_providers
from app.collectors.providers.base import MalformedRecord, PackageQuery, ProviderError, VulnerabilityProvider
from app.config.settings import get_settings


def run(provider: VulnerabilityProvider, ecosystem: str, name: str, version: str, out: Callable[[str], Any] = print) -> bool:
    out(f"LIVE PROVIDER VALIDATION - provider: {provider.display_name} ({provider.describe().get('base_url')})")
    health = provider.health_check()
    out(f"health check: {'ok' if health['ok'] else 'FAILED'} - {health['detail']}")
    if not health["ok"]:
        return False
    if not provider.supports(ecosystem):
        out(f"ecosystem {ecosystem!r} is not covered by this provider")
        return False

    package = PackageQuery(ecosystem, name, normalize_name(ecosystem, name), version)
    try:
        result = provider.query([package])
    except ProviderError as exc:
        out(f"query FAILED: {exc.code} - {exc.message}")
        return False
    identifiers = result.reported.get(package, [])
    out(f"{provider.display_name} reports {len(identifiers)} advisory record(s) for {ecosystem} {name} {version}")

    ok = True
    for identifier in identifiers:
        try:
            record, raw = provider.fetch(identifier)
            normalized = provider.normalize(record, raw)
        except (ProviderError, MalformedRecord) as exc:
            out(f"  {identifier}: FAILED - {exc}")
            ok = False
            continue
        entries = [a for a in normalized["affected"] if a["ecosystem"] == ecosystem and a["package_name"] == package.normalized_name]
        evaluations = [matching.evaluate(ecosystem, version, entry) for entry in entries]
        affected = next((e for e in evaluations if e.status == matching.AFFECTED), None)
        verdict = affected or (evaluations[0] if evaluations else None)
        out(f"  {identifier}  severity={normalized['severity']}  aliases={','.join(normalized['aliases']) or '-'}")
        out(f"      local evaluation: {verdict.status if verdict else 'NO ENTRY FOR THIS PACKAGE'}"
            + (f" ({verdict.affected_range}; fixed in {verdict.fixed or 'no fixed version published'})" if affected else "")
            + (f" - {verdict.reason}" if verdict and not affected else ""))
    return ok


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Live check of the configured vulnerability provider. Uses the network.")
    parser.add_argument("ecosystem", help="pypi, npm, maven, golang, cargo or conan")
    parser.add_argument("name", help="package name, e.g. requests")
    parser.add_argument("version", help="package version, e.g. 2.19.1")
    parser.add_argument("--provider", default=None, help="provider name (default: the first enabled provider)")
    arguments = parser.parse_args(argv)
    providers = build_providers(get_settings())
    if not providers:
        print("No vulnerability provider is enabled (VULNERABILITY_PROVIDERS is empty).")
        return 1
    provider = providers.get(arguments.provider) if arguments.provider else next(iter(providers.values()))
    if provider is None:
        print(f"Unknown provider {arguments.provider!r}. Enabled: {', '.join(providers)}")
        return 1
    return 0 if run(provider, arguments.ecosystem.lower(), arguments.name, arguments.version) else 1


if __name__ == "__main__":
    sys.exit(main())

"""Canonical package names and package URLs (PURLs).

Equivalent spellings of a name must map to one normalised form, per ecosystem:

pypi    PEP 503: lower-case, runs of "-", "_", "." collapse to "-"
npm     lower-case (scope kept)
cargo   lower-case, "_" and "-" are equivalent on crates.io -> "-"
maven   "group:artifact", case preserved (Maven coordinates are case-sensitive)
golang  module path, case preserved (module paths are case-sensitive)
vcpkg, conan, cmake   lower-case
"""

from __future__ import annotations

import re
from urllib.parse import quote

_PEP503 = re.compile(r"[-_.]+")

PURL_TYPES = {
    "pypi": "pypi",
    "npm": "npm",
    "maven": "maven",
    "golang": "golang",
    "cargo": "cargo",
    "conan": "conan",
    "vcpkg": "generic",
    "cmake": "generic",
}


def normalize_name(ecosystem: str, name: str) -> str:
    name = name.strip()
    if ecosystem == "pypi":
        return _PEP503.sub("-", name).lower()
    if ecosystem == "cargo":
        return name.lower().replace("_", "-")
    if ecosystem in {"npm", "vcpkg", "conan", "cmake"}:
        return name.lower()
    return name


def make_purl(ecosystem: str, normalized_name: str, version: str | None) -> str | None:
    """Build a package URL. Returns None when the ecosystem has no PURL mapping."""
    purl_type = PURL_TYPES.get(ecosystem)
    if purl_type is None or not normalized_name:
        return None
    namespace, name = "", normalized_name
    if ecosystem == "maven" and ":" in normalized_name:
        namespace, name = normalized_name.split(":", 1)
    elif ecosystem == "npm" and normalized_name.startswith("@") and "/" in normalized_name:
        namespace, name = normalized_name.split("/", 1)
    elif ecosystem == "golang" and "/" in normalized_name:
        namespace, name = normalized_name.rsplit("/", 1)
        namespace = namespace.lower()
        name = name.lower()
    path = "/".join(quote(part, safe="") for part in namespace.split("/") if part)
    purl = f"pkg:{purl_type}/" + (f"{path}/" if path else "") + quote(name, safe="")
    if version:
        purl += "@" + quote(version, safe="")
    if purl_type == "generic" and ecosystem != "generic":
        purl += f"?package_manager={ecosystem}"
    return purl


def node_id(ecosystem: str, normalized_name: str, version: str | None) -> str:
    return f"{ecosystem}:{normalized_name}@{version if version else 'unresolved'}"

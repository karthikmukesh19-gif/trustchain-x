"""Map the top-level name of an import statement to a dependency of the snapshot.

An import name and a distribution name are different things ("import yaml"
comes from the distribution "PyYAML"). The mapping here is deliberately small:

  NAME_EQUAL          the import name, normalised like a distribution name, equals a dependency in the inventory
  KNOWN_IMPORT_NAME   a short, documented table of distributions whose import name differs

Both are INFERRED: neither is read from the installed package, because
nothing is installed. An import that matches neither and is not part of the
standard library is reported as UNMAPPED, never attached to a dependency.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any

from app.analyzers.normalize import normalize_name

STDLIB = "STDLIB"
DEPENDENCY = "DEPENDENCY"
UNMAPPED = "UNMAPPED"            # third-party by elimination, but no dependency in the inventory matches
AMBIGUOUS = "AMBIGUOUS"          # more than one distribution in the inventory could provide the name

NAME_EQUAL = "NAME_EQUAL"
KNOWN_IMPORT_NAME = "KNOWN_IMPORT_NAME"

_STDLIB = frozenset(sys.stdlib_module_names) | {"__future__", "__main__"}

# import name -> distributions (normalised) that provide it. Only well-known, stable cases.
KNOWN_IMPORT_NAMES: dict[str, tuple[str, ...]] = {
    "yaml": ("pyyaml",), "jose": ("python-jose",), "dotenv": ("python-dotenv",), "bs4": ("beautifulsoup4",),
    "PIL": ("pillow",), "cv2": ("opencv-python", "opencv-python-headless", "opencv-contrib-python"),
    "sklearn": ("scikit-learn",), "skimage": ("scikit-image",), "dateutil": ("python-dateutil",), "jwt": ("pyjwt",),
    "Crypto": ("pycryptodome", "pycrypto"), "Cryptodome": ("pycryptodomex",), "OpenSSL": ("pyopenssl",), "attr": ("attrs",),
    "google.protobuf": ("protobuf",), "magic": ("python-magic",), "multipart": ("python-multipart",), "serial": ("pyserial",),
    "git": ("gitpython",), "dns": ("dnspython",), "bson": ("pymongo",), "gridfs": ("pymongo",),
    "pkg_resources": ("setuptools",), "MySQLdb": ("mysqlclient",), "psycopg2": ("psycopg2", "psycopg2-binary"),
    "zmq": ("pyzmq",), "socks": ("pysocks",), "websocket": ("websocket-client",), "slugify": ("python-slugify",),
    "docx": ("python-docx",), "pptx": ("python-pptx",), "fitz": ("pymupdf",), "telegram": ("python-telegram-bot",),
    "github": ("pygithub",), "ldap": ("python-ldap",), "nacl": ("pynacl",), "kafka": ("kafka-python",),
    "socketio": ("python-socketio",), "engineio": ("python-engineio",), "Levenshtein": ("python-levenshtein", "levenshtein"),
    "markdown": ("markdown",), "jinja2": ("jinja2",), "werkzeug": ("werkzeug",), "passlib": ("passlib",),
    "memcache": ("python-memcached",), "usb": ("pyusb",), "win32api": ("pywin32",), "win32con": ("pywin32",),
    "ruamel.yaml": ("ruamel-yaml",), "setuptools": ("setuptools",), "lxml": ("lxml",),
}


@dataclass
class ImportMapping:
    resolution: str
    top_level: str
    dependencies: list[dict[str, Any]] = field(default_factory=list)   # {"node_id", "name", "normalized_name", "version", "relationship"}
    basis: str | None = None
    note: str | None = None

    @property
    def dependency(self) -> dict[str, Any] | None:
        return self.dependencies[0] if len(self.dependencies) == 1 else None


class DependencyIndex:
    """The Python dependencies of one snapshot, looked up by import name."""

    def __init__(self, dependencies: list[dict[str, Any]], ecosystem: str = "pypi") -> None:
        self.ecosystem = ecosystem
        self._by_name: dict[str, list[dict[str, Any]]] = {}
        for item in dependencies:
            if item.get("ecosystem") != ecosystem:
                continue
            record = {"node_id": item["node_id"], "name": item.get("name"), "normalized_name": item["normalized_name"],
                      "version": item.get("version"), "relationship": item.get("relationship")}
            self._by_name.setdefault(item["normalized_name"], []).append(record)
        for records in self._by_name.values():
            records.sort(key=lambda r: r["node_id"])

    def classify(self, dotted: str) -> ImportMapping:
        """Classify an absolute import by its dotted module name."""
        parts = dotted.split(".")
        top = parts[0]
        # The documented table first, longest prefix first ("google.protobuf" before "google").
        for length in range(min(len(parts), 3), 0, -1):
            known = KNOWN_IMPORT_NAMES.get(".".join(parts[:length]))
            if known:
                found = [record for name in known for record in self._by_name.get(name, [])]
                if found:
                    return self._mapping(top, found, KNOWN_IMPORT_NAME)
        found = self._by_name.get(normalize_name(self.ecosystem, top), [])
        if found:
            return self._mapping(top, found, NAME_EQUAL)
        if top in _STDLIB:
            return ImportMapping(STDLIB, top)
        return ImportMapping(UNMAPPED, top, note="No dependency in the inventory provides this import name by the mapping rules.")

    @staticmethod
    def _mapping(top: str, found: list[dict[str, Any]], basis: str) -> ImportMapping:
        distributions = {record["normalized_name"] for record in found}
        if len(distributions) > 1:
            return ImportMapping(AMBIGUOUS, top, found, basis,
                                 "More than one distribution in the inventory can provide this import name.")
        note = "The inventory holds more than one version of this distribution." if len(found) > 1 else None
        return ImportMapping(DEPENDENCY, top, found, basis, note)

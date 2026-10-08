"""SBOM generation, canonicalisation, integrity verification and comparison.

An SBOM here is always derived from a repository snapshot's dependency
inventory. It is never edited by hand: a different SBOM can only come from a
different snapshot or a newer generator.
"""

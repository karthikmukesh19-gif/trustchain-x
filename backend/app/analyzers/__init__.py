"""Repository analysis: detection, dependency extraction, normalisation and resolution.

Nothing in this package executes repository content. Every parser reads text
and returns data; build scripts (setup.py, conanfile.py, Gradle, CMake) are
either pattern-matched and labelled INFERRED, or reported as not evaluated.
"""

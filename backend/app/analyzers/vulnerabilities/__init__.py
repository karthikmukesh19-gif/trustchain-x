"""Vulnerability matching: version ordering, range evaluation, severity.

Everything here is deterministic and offline. It decides whether an observed
package version falls inside a range published by a vulnerability source; it
says nothing about exploitability, reachability or risk.
"""

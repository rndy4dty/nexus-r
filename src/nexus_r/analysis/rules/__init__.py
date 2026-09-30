"""Rule registry."""

from __future__ import annotations

from nexus_r.analysis.rule import Rule
from nexus_r.analysis.rules.suid_gtfobins import SuidGtfobinsRule


def get_rules() -> list[Rule]:
    """Return instances of all registered rules."""
    return [
        SuidGtfobinsRule(),
    ]


__all__ = ["get_rules"]

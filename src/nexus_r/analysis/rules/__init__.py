"""Rule registry.

Empty in Step 1. Rules will be added in later steps.
"""

from __future__ import annotations

from nexus_r.analysis.rule import Rule


def get_rules() -> list[Rule]:
    """Return instances of all registered rules."""
    return []


__all__ = ["get_rules"]

"""Correlation rule registry.

Empty in Step 11. Correlation rules will be added in later steps.
"""

from __future__ import annotations

from nexus_r.analysis.correlation.rule import CorrelationRule


def get_correlation_rules() -> list[CorrelationRule]:
    """Return instances of all registered correlation rules."""
    return []


__all__ = ["get_correlation_rules"]

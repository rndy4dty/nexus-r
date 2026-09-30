"""Correlation rule registry."""

from __future__ import annotations

from nexus_r.analysis.correlation.rule import CorrelationRule
from nexus_r.analysis.correlation.rules.docker_group_socket import (
    DockerGroupSocketCorrelation,
)


def get_correlation_rules() -> list[CorrelationRule]:
    """Return instances of all registered correlation rules."""
    return [
        DockerGroupSocketCorrelation(),
    ]


__all__ = ["get_correlation_rules"]

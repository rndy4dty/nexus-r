"""Correlation rule registry."""

from __future__ import annotations

from nexus_r.analysis.correlation.rule import CorrelationRule
from nexus_r.analysis.correlation.rules.docker_group_socket import (
    DockerGroupSocketCorrelation,
)
from nexus_r.analysis.correlation.rules.lxd_group import LxdGroupCorrelation


def get_correlation_rules() -> list[CorrelationRule]:
    """Return instances of all registered correlation rules."""
    return [
        DockerGroupSocketCorrelation(),
        LxdGroupCorrelation(),
    ]


__all__ = ["get_correlation_rules"]

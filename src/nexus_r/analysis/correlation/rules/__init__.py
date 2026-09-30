"""Correlation rule registry."""

from __future__ import annotations

from nexus_r.analysis.correlation.rule import CorrelationRule
from nexus_r.analysis.correlation.rules.docker_group_socket import (
    DockerGroupSocketCorrelation,
)
from nexus_r.analysis.correlation.rules.lxd_group import LxdGroupCorrelation
from nexus_r.analysis.correlation.rules.ssh_key_lateral import (
    SshKeyLateralCorrelation,
)


def get_correlation_rules() -> list[CorrelationRule]:
    """Return instances of all registered correlation rules."""
    return [
        DockerGroupSocketCorrelation(),
        LxdGroupCorrelation(),
        SshKeyLateralCorrelation(),
    ]


__all__ = ["get_correlation_rules"]

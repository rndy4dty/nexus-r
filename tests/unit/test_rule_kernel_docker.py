"""Unit tests for KernelOutdatedRule and DockerSocketRule."""

from __future__ import annotations

from nexus_r.analysis import Confidence, Severity
from nexus_r.analysis.rules.docker_socket import DockerSocketRule
from nexus_r.analysis.rules.kernel_outdated import KernelOutdatedRule
from nexus_r.evidence import Evidence, EvidenceStore, EvidenceType


def _system(release: str) -> Evidence:
    return Evidence(
        id="sys-0001",
        type=EvidenceType.SYSTEM,
        source="system",
        data={"kernel_release": release},
    )


def _docker_socket(path: str = "/var/run/docker.sock") -> Evidence:
    return Evidence(
        id="dkr-0001",
        type=EvidenceType.DOCKER,
        source="docker",
        data={
            "kind": "socket",
            "path": path,
            "mode": "0o660",
            "owner_uid": 0,
            "group_gid": 999,
            "world_writable": False,
        },
    )


def test_kernel_empty() -> None:
    assert KernelOutdatedRule().evaluate(EvidenceStore()) == []


def test_kernel_old() -> None:
    store = EvidenceStore()
    store.add(_system("4.4.0-100-generic"))
    results = KernelOutdatedRule().evaluate(store)
    assert len(results) == 1
    assert results[0].severity == Severity.MEDIUM
    assert results[0].confidence == Confidence.LOW


def test_kernel_modern() -> None:
    store = EvidenceStore()
    store.add(_system("6.8.0-31-generic"))
    assert KernelOutdatedRule().evaluate(store) == []


def test_kernel_invalid_format() -> None:
    store = EvidenceStore()
    store.add(_system("unknown"))
    assert KernelOutdatedRule().evaluate(store) == []


def test_docker_empty() -> None:
    assert DockerSocketRule().evaluate(EvidenceStore()) == []


def test_docker_socket_detected() -> None:
    store = EvidenceStore()
    store.add(_docker_socket())
    results = DockerSocketRule().evaluate(store)
    assert len(results) == 1
    assert results[0].severity == Severity.CRITICAL
    assert results[0].confidence == Confidence.MEDIUM


def test_docker_ignores_process_kind() -> None:
    store = EvidenceStore()
    store.add(
        Evidence(
            id="dkr-0001",
            type=EvidenceType.DOCKER,
            source="docker",
            data={"kind": "process", "in_container": False},
        )
    )
    assert DockerSocketRule().evaluate(store) == []

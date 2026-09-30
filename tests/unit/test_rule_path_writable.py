"""Unit tests for PathWritableRule."""

from __future__ import annotations

import os

from nexus_r.analysis import Confidence, Severity
from nexus_r.analysis.rules.path_writable import PathWritableRule
from nexus_r.evidence import Evidence, EvidenceStore, EvidenceType


def _path_entry(
    path: str,
    *,
    world: bool = False,
    group: bool = False,
    is_dir: bool = True,
    owner_uid: int = 0,
) -> Evidence:
    return Evidence(
        id=f"env-{abs(hash(path)) % 10000:04d}",
        type=EvidenceType.OTHER,
        source="environment",
        data={
            "kind": "path_entry",
            "path": path,
            "mode": "0o777" if world else "0o755",
            "owner_uid": owner_uid,
            "group_gid": 0,
            "world_writable": world,
            "group_writable": group,
            "is_dir": is_dir,
        },
    )


def test_empty_store() -> None:
    assert PathWritableRule().evaluate(EvidenceStore()) == []


def test_world_writable_path() -> None:
    store = EvidenceStore()
    store.add(_path_entry("/tmp/evil", world=True, owner_uid=0))
    results = PathWritableRule().evaluate(store)
    assert len(results) == 1
    assert results[0].severity == Severity.HIGH
    assert results[0].confidence == Confidence.HIGH


def test_group_writable_path() -> None:
    store = EvidenceStore()
    store.add(_path_entry("/opt/shared", group=True, owner_uid=0))
    results = PathWritableRule().evaluate(store)
    assert len(results) == 1


def test_safe_path_ignored() -> None:
    store = EvidenceStore()
    store.add(_path_entry("/usr/bin"))
    assert PathWritableRule().evaluate(store) == []


def test_non_directory_ignored() -> None:
    store = EvidenceStore()
    store.add(_path_entry("/tmp/evil", world=True, is_dir=False))
    assert PathWritableRule().evaluate(store) == []


def test_own_directory_ignored() -> None:
    """A writable directory owned by the current user is not a privesc."""
    store = EvidenceStore()
    store.add(_path_entry("/home/me/.local/bin", group=True, owner_uid=os.getuid()))
    assert PathWritableRule().evaluate(store) == []

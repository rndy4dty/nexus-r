"""Unit tests for UsersCollector."""

from __future__ import annotations

from nexus_r.collectors.users import UsersCollector
from nexus_r.evidence import EvidenceType


def test_users_collector_runs() -> None:
    items = UsersCollector().collect()
    assert len(items) >= 1


def test_users_collector_has_user_and_group() -> None:
    items = UsersCollector().collect()
    types = {i.type for i in items}
    assert EvidenceType.USER in types
    assert EvidenceType.GROUP in types


def test_users_collector_has_root() -> None:
    items = UsersCollector().collect()
    users = [i for i in items if i.type == EvidenceType.USER]
    roots = [u for u in users if u.data.get("uid") == 0]
    assert roots, "expected at least one user with uid 0"


def test_users_collector_ids_unique() -> None:
    items = UsersCollector().collect()
    ids = [i.id for i in items]
    assert len(ids) == len(set(ids))


def test_users_collector_prefixes() -> None:
    items = UsersCollector().collect()
    for item in items:
        if item.type == EvidenceType.USER:
            assert item.id.startswith("usr-")
        elif item.type == EvidenceType.GROUP:
            assert item.id.startswith("grp-")

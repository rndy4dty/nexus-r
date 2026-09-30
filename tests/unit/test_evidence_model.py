"""Unit tests for the Evidence model and EvidenceStore."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from nexus_r.evidence import Evidence, EvidenceStore, EvidenceType


def test_evidence_minimal_construction() -> None:
    ev = Evidence(
        id="sys-001",
        type=EvidenceType.SYSTEM,
        source="system_collector",
        data={"kernel": "6.8.0"},
    )
    assert ev.id == "sys-001"
    assert ev.type == EvidenceType.SYSTEM
    assert ev.source == "system_collector"
    assert ev.data == {"kernel": "6.8.0"}
    assert ev.tags == ()
    assert ev.collected_at.tzinfo is not None


def test_evidence_is_frozen() -> None:
    ev = Evidence(id="x", type=EvidenceType.OTHER, source="s")
    with pytest.raises(ValidationError):
        ev.id = "y"  # type: ignore[misc]


def test_evidence_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        Evidence(
            id="x",
            type=EvidenceType.OTHER,
            source="s",
            unexpected="nope",  # type: ignore[call-arg]
        )


def test_evidence_requires_non_empty_id_and_source() -> None:
    with pytest.raises(ValidationError):
        Evidence(id="", type=EvidenceType.OTHER, source="s")
    with pytest.raises(ValidationError):
        Evidence(id="x", type=EvidenceType.OTHER, source="")


def test_evidence_to_json_dict_serializes_datetime() -> None:
    ev = Evidence(id="x", type=EvidenceType.OTHER, source="s")
    payload = ev.to_json_dict()
    assert isinstance(payload["collected_at"], str)
    assert "T" in payload["collected_at"]


def test_store_add_and_count() -> None:
    store = EvidenceStore()
    assert store.count() == 0
    store.add(Evidence(id="a", type=EvidenceType.SYSTEM, source="s"))
    store.add(Evidence(id="b", type=EvidenceType.USER, source="s"))
    assert store.count() == 2
    assert len(store) == 2


def test_store_add_many_preserves_order() -> None:
    store = EvidenceStore()
    items = [
        Evidence(id="a", type=EvidenceType.SYSTEM, source="s"),
        Evidence(id="b", type=EvidenceType.USER, source="s"),
        Evidence(id="c", type=EvidenceType.FILE, source="s"),
    ]
    store.add_many(items)
    assert [ev.id for ev in store.all()] == ["a", "b", "c"]


def test_store_filter_by_type_and_source() -> None:
    store = EvidenceStore()
    store.add_many(
        [
            Evidence(id="a", type=EvidenceType.SYSTEM, source="sys"),
            Evidence(id="b", type=EvidenceType.USER, source="users"),
            Evidence(id="c", type=EvidenceType.SYSTEM, source="sys"),
        ]
    )
    assert {ev.id for ev in store.by_type(EvidenceType.SYSTEM)} == {"a", "c"}
    assert {ev.id for ev in store.by_source("users")} == {"b"}


def test_store_clear() -> None:
    store = EvidenceStore()
    store.add(Evidence(id="a", type=EvidenceType.SYSTEM, source="s"))
    store.clear()
    assert store.count() == 0


def test_store_to_list_is_json_serializable() -> None:
    import json

    store = EvidenceStore()
    store.add(Evidence(id="a", type=EvidenceType.SYSTEM, source="s"))
    payload = store.to_list()
    assert isinstance(payload, list)
    assert payload[0]["id"] == "a"
    # Must not raise
    json.dumps(payload)


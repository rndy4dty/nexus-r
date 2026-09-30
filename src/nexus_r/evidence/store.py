
"""In-memory evidence store.

The store is a thin, deterministic container. It performs no analysis,
no severity scoring, and no interpretation. Its only responsibilities:

    - Append evidence.
    - Retrieve evidence (all, by type, by source).
    - Report counts.
    - Produce a JSON-serializable list for the reporter.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from nexus_r.evidence.model import Evidence, EvidenceType


class EvidenceStore:
    """In-memory container for Evidence items.

    Ordering: evidence is stored in insertion order so reports remain
    deterministic across runs with the same collector order.
    """

    def __init__(self) -> None:
        self._items: list[Evidence] = []

    def add(self, evidence: Evidence) -> None:
        """Append a single Evidence item."""
        self._items.append(evidence)

    def add_many(self, items: Iterable[Evidence]) -> None:
        """Append multiple Evidence items in iteration order."""
        for item in items:
            self.add(item)

    def all(self) -> list[Evidence]:
        """Return a shallow copy of all evidence in insertion order."""
        return list(self._items)

    def by_type(self, evidence_type: EvidenceType) -> list[Evidence]:
        """Return evidence filtered by type."""
        return [item for item in self._items if item.type == evidence_type]

    def by_source(self, source: str) -> list[Evidence]:
        """Return evidence filtered by collector source name."""
        return [item for item in self._items if item.source == source]

    def count(self) -> int:
        """Return total number of stored evidence items."""
        return len(self._items)

    def clear(self) -> None:
        """Remove all stored evidence."""
        self._items.clear()

    def to_list(self) -> list[dict]:
        """Return JSON-serializable list of evidence dicts."""
        return [item.to_json_dict() for item in self._items]

    def __iter__(self) -> Iterator[Evidence]:
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

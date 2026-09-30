"""Base collector.

Collectors acquire data from the system. They produce structured Evidence
and must not decide whether something is a vulnerability (ADR-001 §3.1, §3.2).
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from nexus_r.evidence import Evidence


class BaseCollector(ABC):
    """Abstract base class for collectors."""

    name: str = "base"
    requires_root: bool = False

    def __init__(self) -> None:
        self._counter: int = 0

    def _next_id(self, prefix: str) -> str:
        """Return a deterministic per-instance evidence ID."""
        self._counter += 1
        return f"{prefix}-{self._counter:04d}"

    @abstractmethod
    def collect(self) -> list[Evidence]:
        """Collect evidence from the system. Must not raise for expected issues."""
        raise NotImplementedError

"""Structured evidence model.

Evidence is the normalized, structured representation of an observation
collected from the Linux system. Evidence must not encode severity or
findings — those belong to the analysis layer (ADR-001 §3.2).

This model is the contract between collectors/normalizer and every
downstream consumer (store, reporter, future rule engine).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EvidenceType(str, Enum):
    """Canonical categories of evidence produced by NEXUS-R.

    The list is intentionally small in V0.1 and can grow per milestone.
    """

    SYSTEM = "system"
    USER = "user"
    GROUP = "group"
    SUDO = "sudo"
    SESSION = "session"
    FILE = "file"
    SUID = "suid"
    SGID = "sgid"
    WRITABLE = "writable"
    PROCESS = "process"
    SERVICE = "service"
    SYSTEMD = "systemd"
    CRON = "cron"
    CAPABILITY = "capability"
    NETWORK = "network"
    PACKAGE = "package"
    DOCKER = "docker"
    KUBERNETES = "kubernetes"
    OTHER = "other"


def _utc_now() -> datetime:
    """Return current UTC time as timezone-aware datetime."""
    return datetime.now(timezone.utc)


class Evidence(BaseModel):
    """A single structured observation.

    Attributes:
        id: Deterministic-looking identifier produced by the collector.
        type: Evidence category (see EvidenceType).
        source: Collector name that produced this evidence.
        collected_at: UTC timestamp when evidence was produced.
        data: Structured payload (JSON-serializable).
        tags: Optional free-form tags for later correlation.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(..., min_length=1)
    type: EvidenceType
    source: str = Field(..., min_length=1)
    collected_at: datetime = Field(default_factory=_utc_now)
    data: dict[str, Any] = Field(default_factory=dict)
    tags: tuple[str, ...] = ()

    def to_json_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict representation."""
        return self.model_dump(mode="json")


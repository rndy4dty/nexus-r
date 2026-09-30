"""Finding model.

A Finding is the output of analysis. It references evidence, carries
severity and confidence separately (ADR-001 §3.6), and provides
validation steps for human validation (ADR-001 §3.7).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Finding(BaseModel):
    """Structured finding produced by a rule."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(..., min_length=1)
    rule_id: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    description: str = ""
    category: str = "privilege-escalation"
    severity: Severity
    confidence: Confidence
    evidence_ids: tuple[str, ...] = ()
    validation_steps: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    created_at: datetime = Field(default_factory=_utc_now)

    def to_json_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

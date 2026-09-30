"""Attack path model.

An AttackPath links findings that, taken together, allow a concrete
escalation from a starting position to a target privilege. It is the
output of the correlation engine (V0.3, ADR-001 §2).

An AttackPath is always derived from findings - it must never
introduce new claims that are not backed by at least one finding.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from nexus_r.analysis.finding import Confidence, Severity


class AttackPathStatus(str, Enum):
    """Whether the attack path is plausible or just a hypothesis."""

    PLAUSIBLE = "plausible"
    HYPOTHESIS = "hypothesis"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AttackPath(BaseModel):
    """A chain of findings that enables privilege escalation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(..., min_length=1)
    rule_id: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    narrative: str = ""
    category: str = "privilege-escalation"
    status: AttackPathStatus = AttackPathStatus.PLAUSIBLE
    severity: Severity
    confidence: Confidence
    finding_ids: tuple[str, ...] = ()
    entry_point: str = ""
    target: str = "root"
    validation_steps: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    created_at: datetime = Field(default_factory=_utc_now)

    def to_json_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

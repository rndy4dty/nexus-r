"""Cron collector.

Reads cron files and cron directories. Read-only. Does not judge -
that is the rule engine's job (ADR-001 §3.2).
"""

from __future__ import annotations

from pathlib import Path

from nexus_r.collectors.base import BaseCollector
from nexus_r.evidence import Evidence, EvidenceType

CRON_FILES = [
    Path("/etc/crontab"),
]

CRON_DIRS = [
    Path("/etc/cron.d"),
    Path("/var/spool/cron"),
    Path("/var/spool/cron/crontabs"),
    Path("/etc/cron.hourly"),
    Path("/etc/cron.daily"),
    Path("/etc/cron.weekly"),
    Path("/etc/cron.monthly"),
]


class CronCollector(BaseCollector):
    """Collects cron jobs and cron directories."""

    name = "cron"
    requires_root = False

    def collect(self) -> list[Evidence]:
        items: list[Evidence] = []
        for path in CRON_FILES:
            if path.is_file():
                items.extend(self._read_cron_file(path))
        for path in CRON_DIRS:
            if path.is_dir():
                items.extend(self._read_cron_dir(path))
        return items

    def _read_cron_file(self, path: Path) -> list[Evidence]:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return []

        items: list[Evidence] = []
        for lineno, raw in enumerate(content.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            items.append(
                Evidence(
                    id=self._next_id("cron"),
                    type=EvidenceType.CRON,
                    source=self.name,
                    data={
                        "path": str(path),
                        "line": lineno,
                        "entry": line,
                        "kind": "entry",
                    },
                    tags=("cron", "entry"),
                )
            )
        return items

    def _read_cron_dir(self, path: Path) -> list[Evidence]:
        items: list[Evidence] = []
        try:
            children = sorted(path.iterdir())
        except (OSError, PermissionError):
            return items

        for child in children:
            if not child.is_file():
                continue
            items.append(
                Evidence(
                    id=self._next_id("cron"),
                    type=EvidenceType.CRON,
                    source=self.name,
                    data={
                        "path": str(child),
                        "kind": "script",
                        "name": child.name,
                    },
                    tags=("cron", "script"),
                )
            )
        return items

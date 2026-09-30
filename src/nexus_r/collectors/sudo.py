"""Sudo configuration collector.

Reads /etc/sudoers and /etc/sudoers.d/*. Read-only. Does not judge -
that is the rule engine's job (ADR-001 §3.2).

Note: /etc/sudoers is usually mode 0440 root:root, so an unprivileged
user cannot read it. When that happens, we record an evidence item
with `readable: false` so the report reflects the actual state.
"""

from __future__ import annotations

from pathlib import Path

from nexus_r.collectors.base import BaseCollector
from nexus_r.evidence import Evidence, EvidenceType

SUDOERS = Path("/etc/sudoers")
SUDOERS_D = Path("/etc/sudoers.d")


class SudoCollector(BaseCollector):
    """Collects sudoers entries."""

    name = "sudo"
    requires_root = False

    def collect(self) -> list[Evidence]:
        items: list[Evidence] = []
        paths: list[Path] = []

        if SUDOERS.exists():
            paths.append(SUDOERS)

        if SUDOERS_D.is_dir():
            try:
                for p in sorted(SUDOERS_D.iterdir()):
                    if p.is_file():
                        paths.append(p)
            except (OSError, PermissionError):
                pass

        for path in paths:
            items.extend(self._read_file(path))

        return items

    def _read_file(self, path: Path) -> list[Evidence]:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return [
                Evidence(
                    id=self._next_id("sudo"),
                    type=EvidenceType.SUDO,
                    source=self.name,
                    data={
                        "path": str(path),
                        "readable": False,
                    },
                    tags=("sudo", "unreadable"),
                )
            ]

        items: list[Evidence] = []
        for lineno, raw in enumerate(content.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            items.append(
                Evidence(
                    id=self._next_id("sudo"),
                    type=EvidenceType.SUDO,
                    source=self.name,
                    data={
                        "path": str(path),
                        "line": lineno,
                        "entry": line,
                        "readable": True,
                    },
                    tags=("sudo", "rule"),
                )
            )
        return items

"""Writable sensitive files collector.

Checks permission flags of security-relevant paths. Read-only. Does
not judge - that is the rule engine's job (ADR-001 §3.2).
"""

from __future__ import annotations

from pathlib import Path

from nexus_r.collectors.base import BaseCollector
from nexus_r.evidence import Evidence, EvidenceType

SENSITIVE_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/sudoers.d",
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/hosts",
    "/etc/ssh/sshd_config",
    "/etc/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/root",
    "/root/.ssh",
]


class WritableCollector(BaseCollector):
    """Collects permission info for sensitive paths."""

    name = "writable"
    requires_root = False

    def collect(self) -> list[Evidence]:
        items: list[Evidence] = []
        for raw in SENSITIVE_PATHS:
            path = Path(raw)
            try:
                st = path.stat()
            except (OSError, PermissionError):
                continue

            mode = st.st_mode & 0o7777
            items.append(
                Evidence(
                    id=self._next_id("wrt"),
                    type=EvidenceType.WRITABLE,
                    source=self.name,
                    data={
                        "path": raw,
                        "mode": oct(mode),
                        "owner_uid": st.st_uid,
                        "group_gid": st.st_gid,
                        "world_writable": bool(mode & 0o002),
                        "group_writable": bool(mode & 0o020),
                        "owner_writable": bool(mode & 0o200),
                        "is_dir": path.is_dir(),
                    },
                    tags=("writable", "sensitive"),
                )
            )
        return items

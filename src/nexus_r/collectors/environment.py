"""Environment variable collector.

Collects process environment and PATH entries. Redacts variables whose
name suggests a secret. Read-only. Does not judge - that is the rule
engine's job (ADR-001 §3.2).
"""

from __future__ import annotations

import os
from pathlib import Path

from nexus_r.collectors.base import BaseCollector
from nexus_r.evidence import Evidence, EvidenceType

SECRET_HINTS = ("SECRET", "TOKEN", "PASSWORD", "PASSWD", "API_KEY", "PRIVATE")


class EnvironmentCollector(BaseCollector):
    """Collects environment variables and PATH entries."""

    name = "environment"
    requires_root = False

    def collect(self) -> list[Evidence]:
        items: list[Evidence] = []
        items.append(self._collect_env())
        items.extend(self._collect_path_entries())
        return items

    def _collect_env(self) -> Evidence:
        env: dict[str, str] = {}
        for key, value in os.environ.items():
            if any(h in key.upper() for h in SECRET_HINTS):
                env[key] = "<redacted>"
            else:
                env[key] = value
        return Evidence(
            id=self._next_id("env"),
            type=EvidenceType.OTHER,
            source=self.name,
            data={"kind": "env", "variables": env},
            tags=("environment",),
        )

    def _collect_path_entries(self) -> list[Evidence]:
        items: list[Evidence] = []
        path_value = os.environ.get("PATH", "")
        seen: set[str] = set()

        for entry in path_value.split(os.pathsep):
            if not entry or entry in seen:
                continue
            seen.add(entry)

            p = Path(entry)
            if not p.is_dir():
                continue

            try:
                st = p.stat()
            except (OSError, PermissionError):
                continue

            mode = st.st_mode & 0o7777
            items.append(
                Evidence(
                    id=self._next_id("env"),
                    type=EvidenceType.OTHER,
                    source=self.name,
                    data={
                        "kind": "path_entry",
                        "path": entry,
                        "mode": oct(mode),
                        "owner_uid": st.st_uid,
                        "group_gid": st.st_gid,
                        "world_writable": bool(mode & 0o002),
                        "group_writable": bool(mode & 0o020),
                        "is_dir": True,
                    },
                    tags=("environment", "path"),
                )
            )
        return items

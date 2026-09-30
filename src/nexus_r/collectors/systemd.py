"""Systemd unit file collector.

Scans common unit directories for .service/.socket/.timer files and
records their permissions.
"""

from __future__ import annotations

from pathlib import Path

from nexus_r.collectors.base import BaseCollector
from nexus_r.evidence import Evidence, EvidenceType

UNIT_DIRS = [
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/system",
]


class SystemdCollector(BaseCollector):
    """Collects systemd unit files and their permissions."""

    name = "systemd"
    requires_root = False

    def collect(self) -> list[Evidence]:
        items: list[Evidence] = []
        seen: set[str] = set()

        for raw in UNIT_DIRS:
            root = Path(raw)
            if not root.is_dir():
                continue
            for path in self._iter_units(root):
                key = str(path)
                if key in seen:
                    continue
                seen.add(key)
                ev = self._inspect(path)
                if ev is not None:
                    items.append(ev)

        return items

    @staticmethod
    def _iter_units(root: Path):
        try:
            for p in sorted(root.iterdir()):
                if p.is_file() and p.suffix in (".service", ".socket", ".timer"):
                    yield p
        except (OSError, PermissionError):
            return

    def _inspect(self, path: Path) -> Evidence | None:
        try:
            st = path.stat()
        except (OSError, PermissionError):
            return None

        mode = st.st_mode & 0o7777
        return Evidence(
            id=self._next_id("sysd"),
            type=EvidenceType.SYSTEMD,
            source=self.name,
            data={
                "path": str(path),
                "mode": oct(mode),
                "owner_uid": st.st_uid,
                "group_gid": st.st_gid,
                "world_writable": bool(mode & 0o002),
                "group_writable": bool(mode & 0o020),
                "owner_writable": bool(mode & 0o200),
            },
            tags=("systemd", "unit"),
        )

"""SUID/SGID collector.

Finds SUID and SGID binaries on the filesystem. Does not judge them -
that is the rule engine's job (ADR-001 §3.2).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from nexus_r.collectors.base import BaseCollector
from nexus_r.evidence import Evidence, EvidenceType

SEARCH_ROOTS = [
    "/usr",
    "/bin",
    "/sbin",
    "/opt",
    "/usr/local",
    "/var",
    "/tmp",
    "/home",
]


class SuidCollector(BaseCollector):
    """Collects SUID and SGID binaries."""

    name = "suid"
    requires_root = False

    def collect(self) -> list[Evidence]:
        items: list[Evidence] = []
        seen: set[str] = set()

        for root in SEARCH_ROOTS:
            if not Path(root).exists():
                continue
            for path in self._walk(root):
                if path in seen:
                    continue
                seen.add(path)
                ev = self._inspect(path)
                if ev is not None:
                    items.append(ev)

        return items

    def _walk(self, root: str):
        for dirpath, _dirnames, filenames in os.walk(root, onerror=lambda _e: None):
            for name in filenames:
                yield os.path.join(dirpath, name)

    def _inspect(self, path: str) -> Evidence | None:
        try:
            st = os.stat(path, follow_symlinks=False)
        except (OSError, PermissionError):
            return None

        mode = st.st_mode
        is_suid = bool(mode & stat.S_ISUID)
        is_sgid = bool(mode & stat.S_ISGID)

        if not (is_suid or is_sgid):
            return None

        if is_suid:
            ev_type = EvidenceType.SUID
            prefix = "suid"
            tags = ("suid",)
        else:
            ev_type = EvidenceType.SGID
            prefix = "sgid"
            tags = ("sgid",)

        return Evidence(
            id=self._next_id(prefix),
            type=ev_type,
            source=self.name,
            data={
                "path": path,
                "mode": oct(mode & 0o7777),
                "owner_uid": st.st_uid,
                "group_gid": st.st_gid,
                "size": st.st_size,
            },
            tags=tags,
        )

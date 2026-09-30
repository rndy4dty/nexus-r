"""SUID/SGID collector.

Finds SUID and SGID binaries on the filesystem. Does not judge them -
that is the rule engine's job (ADR-001 §3.2).

Deduplicates by inode to avoid reporting the same file twice through
symlinked paths (e.g. /bin -> /usr/bin on modern Ubuntu/Debian).
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
        seen_inodes: set[tuple[int, int]] = set()

        for root in SEARCH_ROOTS:
            if not Path(root).exists():
                continue
            for path in self._walk(root):
                ev = self._inspect(path, seen_inodes)
                if ev is not None:
                    items.append(ev)

        return items

    def _walk(self, root: str):
        for dirpath, _dirnames, filenames in os.walk(root, onerror=lambda _e: None):
            for name in filenames:
                yield os.path.join(dirpath, name)

    def _inspect(
        self, path: str, seen_inodes: set[tuple[int, int]]
    ) -> Evidence | None:
        try:
            st = os.stat(path, follow_symlinks=False)
        except (OSError, PermissionError):
            return None

        mode = st.st_mode
        is_suid = bool(mode & stat.S_ISUID)
        is_sgid = bool(mode & stat.S_ISGID)

        if not (is_suid or is_sgid):
            return None

        # Deduplicate by (device, inode)
        key = (st.st_dev, st.st_ino)
        if key in seen_inodes:
            return None
        seen_inodes.add(key)

        # Resolve real path for a canonical location
        try:
            real_path = str(Path(path).resolve(strict=False))
        except OSError:
            real_path = path

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
                "real_path": real_path,
                "mode": oct(mode & 0o7777),
                "owner_uid": st.st_uid,
                "group_gid": st.st_gid,
                "size": st.st_size,
                "inode": st.st_ino,
                "device": st.st_dev,
            },
            tags=tags,
        )

"""Users and groups collector.

Reads /etc/passwd and /etc/group directly. No subprocess is used.
"""

from __future__ import annotations

from pathlib import Path

from nexus_r.collectors.base import BaseCollector
from nexus_r.evidence import Evidence, EvidenceType

PASSWD_PATH = Path("/etc/passwd")
GROUP_PATH = Path("/etc/group")

NOLOGIN_SHELLS = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false"}


class UsersCollector(BaseCollector):
    """Collects user and group entries."""

    name = "users"
    requires_root = False

    def collect(self) -> list[Evidence]:
        items: list[Evidence] = []
        items.extend(self._collect_users())
        items.extend(self._collect_groups())
        return items

    def _collect_users(self) -> list[Evidence]:
        if not PASSWD_PATH.exists():
            return []

        items: list[Evidence] = []
        try:
            content = PASSWD_PATH.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 7:
                continue

            name, _pw, uid_s, gid_s, gecos, home, shell = parts[:7]
            try:
                uid = int(uid_s)
                gid = int(gid_s)
            except ValueError:
                continue

            tags = ["user"]
            if uid == 0:
                tags.append("root")
            elif uid < 1000:
                tags.append("system")
            if shell not in NOLOGIN_SHELLS:
                tags.append("login_shell")

            items.append(
                Evidence(
                    id=self._next_id("usr"),
                    type=EvidenceType.USER,
                    source=self.name,
                    data={
                        "name": name,
                        "uid": uid,
                        "gid": gid,
                        "gecos": gecos,
                        "home": home,
                        "shell": shell,
                    },
                    tags=tuple(tags),
                )
            )
        return items

    def _collect_groups(self) -> list[Evidence]:
        if not GROUP_PATH.exists():
            return []

        items: list[Evidence] = []
        try:
            content = GROUP_PATH.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) < 4:
                continue

            name, _pw, gid_s, members_s = parts[:4]
            try:
                gid = int(gid_s)
            except ValueError:
                continue

            members = [m for m in members_s.split(",") if m]

            items.append(
                Evidence(
                    id=self._next_id("grp"),
                    type=EvidenceType.GROUP,
                    source=self.name,
                    data={
                        "name": name,
                        "gid": gid,
                        "members": members,
                    },
                    tags=("group",),
                )
            )
        return items

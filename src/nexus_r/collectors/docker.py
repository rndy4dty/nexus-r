"""Docker information collector.

Detects the Docker socket and whether we are running inside a container.

Sockets are deduplicated by (device, inode) so that symlinked paths
(e.g. /var/run -> /run) do not produce duplicate evidence.
"""

from __future__ import annotations

from pathlib import Path

from nexus_r.collectors.base import BaseCollector
from nexus_r.evidence import Evidence, EvidenceType

DOCKER_SOCKETS = [
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/run/containerd/containerd.sock",
]


class DockerCollector(BaseCollector):
    """Collects Docker socket info and container signals."""

    name = "docker"
    requires_root = False

    def collect(self) -> list[Evidence]:
        items: list[Evidence] = []
        seen_inodes: set[tuple[int, int]] = set()

        for raw in DOCKER_SOCKETS:
            path = Path(raw)
            try:
                st = path.stat()
            except (OSError, PermissionError):
                continue

            key = (st.st_dev, st.st_ino)
            if key in seen_inodes:
                continue
            seen_inodes.add(key)

            items.append(
                Evidence(
                    id=self._next_id("dkr"),
                    type=EvidenceType.DOCKER,
                    source=self.name,
                    data={
                        "kind": "socket",
                        "path": raw,
                        "mode": oct(st.st_mode & 0o7777),
                        "owner_uid": st.st_uid,
                        "group_gid": st.st_gid,
                        "world_writable": bool(st.st_mode & 0o002),
                        "inode": st.st_ino,
                        "device": st.st_dev,
                    },
                    tags=("docker", "socket"),
                )
            )

        items.append(self._process_evidence())
        return items

    def _process_evidence(self) -> Evidence:
        return Evidence(
            id=self._next_id("dkr"),
            type=EvidenceType.DOCKER,
            source=self.name,
            data={
                "kind": "process",
                "in_container": Path("/.dockerenv").exists()
                or Path("/run/.containerenv").exists(),
                "cgroup_hint": self._cgroup_hint(),
            },
            tags=("docker", "process"),
        )

    @staticmethod
    def _cgroup_hint() -> str | None:
        try:
            text = Path("/proc/self/cgroup").read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            return None
        for line in text.splitlines():
            if "docker" in line or "kubepods" in line or "containerd" in line:
                return line
        return None

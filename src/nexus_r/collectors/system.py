"""System collector.

Collects basic host information: hostname, kernel, OS release, uptime,
architecture.
"""

from __future__ import annotations

from pathlib import Path

from nexus_r.collectors.base import BaseCollector
from nexus_r.evidence import Evidence, EvidenceType


class SystemCollector(BaseCollector):
    """Collects basic host information."""

    name = "system"
    requires_root = False

    def collect(self) -> list[Evidence]:
        items: list[Evidence] = []

        hostname = self._read_hostname()
        if hostname:
            items.append(
                Evidence(
                    id=self._next_id("sys"),
                    type=EvidenceType.SYSTEM,
                    source=self.name,
                    data={"hostname": hostname},
                    tags=("system", "host"),
                )
            )

        kernel = self._read_kernel()
        if kernel:
            items.append(
                Evidence(
                    id=self._next_id("sys"),
                    type=EvidenceType.SYSTEM,
                    source=self.name,
                    data={"kernel_release": kernel},
                    tags=("system", "kernel"),
                )
            )

        arch = self._read_arch()
        if arch:
            items.append(
                Evidence(
                    id=self._next_id("sys"),
                    type=EvidenceType.SYSTEM,
                    source=self.name,
                    data={"architecture": arch},
                    tags=("system", "arch"),
                )
            )

        os_release = self._read_os_release()
        if os_release:
            items.append(
                Evidence(
                    id=self._next_id("sys"),
                    type=EvidenceType.SYSTEM,
                    source=self.name,
                    data={"os_release": os_release},
                    tags=("system", "os"),
                )
            )

        uptime = self._read_uptime()
        if uptime:
            items.append(
                Evidence(
                    id=self._next_id("sys"),
                    type=EvidenceType.SYSTEM,
                    source=self.name,
                    data={"uptime_seconds": uptime},
                    tags=("system", "uptime"),
                )
            )

        return items

    @staticmethod
    def _read_hostname() -> str | None:
        path = Path("/etc/hostname")
        if path.exists():
            try:
                return path.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                pass
        return None

    @staticmethod
    def _read_kernel() -> str | None:
        path = Path("/proc/sys/kernel/osrelease")
        if path.exists():
            try:
                return path.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                pass
        return None

    @staticmethod
    def _read_arch() -> str | None:
        import platform

        try:
            return platform.machine() or None
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _read_uptime() -> float | None:
        path = Path("/proc/uptime")
        if not path.exists():
            return None
        try:
            first = path.read_text(encoding="utf-8").split()[0]
            return float(first)
        except (OSError, ValueError, IndexError):
            return None

    @staticmethod
    def _read_os_release() -> dict[str, str]:
        path = Path("/etc/os-release")
        if not path.exists():
            return {}
        result: dict[str, str] = {}
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip().strip('"').strip("'")
            result[key.strip()] = value
        return result

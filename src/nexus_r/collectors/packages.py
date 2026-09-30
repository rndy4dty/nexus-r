"""Installed packages collector (dpkg).

Reads /var/lib/dpkg/status on Debian-based systems. The file is
readable by regular users, so no root is required. RPM-based systems
are not supported in this version.
"""

from __future__ import annotations

from pathlib import Path

from nexus_r.collectors.base import BaseCollector
from nexus_r.evidence import Evidence, EvidenceType

DPKG_STATUS = Path("/var/lib/dpkg/status")


class PackagesCollector(BaseCollector):
    """Collects installed dpkg packages."""

    name = "packages"
    requires_root = False

    def collect(self) -> list[Evidence]:
        if not DPKG_STATUS.exists():
            return []

        try:
            content = DPKG_STATUS.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            return []

        items: list[Evidence] = []
        for block in content.split("\n\n"):
            parsed = self._parse_block(block)
            if parsed is None:
                continue
            name, version, arch, status = parsed
            if "installed" not in status:
                continue
            items.append(
                Evidence(
                    id=self._next_id("pkg"),
                    type=EvidenceType.PACKAGE,
                    source=self.name,
                    data={
                        "name": name,
                        "version": version,
                        "architecture": arch,
                    },
                    tags=("package", "dpkg"),
                )
            )
        return items

    @staticmethod
    def _parse_block(block: str) -> tuple[str, str, str, str] | None:
        name = version = arch = status = ""
        for line in block.splitlines():
            if line.startswith("Package:"):
                name = line.split(":", 1)[1].strip()
            elif line.startswith("Version:"):
                version = line.split(":", 1)[1].strip()
            elif line.startswith("Architecture:"):
                arch = line.split(":", 1)[1].strip()
            elif line.startswith("Status:"):
                status = line.split(":", 1)[1].strip()
        if name and version:
            return name, version, arch, status
        return None

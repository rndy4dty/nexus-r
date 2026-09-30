"""Systemd services collector.

Lists running systemd services via `systemctl list-units`. Silently
returns nothing when systemctl is not available.
"""

from __future__ import annotations

from nexus_r.collectors.base import BaseCollector
from nexus_r.evidence import Evidence, EvidenceType
from nexus_r.utils.shell import run_command


class ServicesCollector(BaseCollector):
    """Collects running systemd services."""

    name = "services"
    requires_root = False

    def collect(self) -> list[Evidence]:
        probe = run_command(["systemctl", "--version"],
                            allow=frozenset({"systemctl"}))
        if probe.returncode != 0:
            return []

        result = run_command(
            [
                "systemctl",
                "list-units",
                "--type=service",
                "--state=running",
                "--no-legend",
                "--no-pager",
                "--plain",
            ],
            timeout=15.0,
            allow=frozenset({"systemctl"}),
        )
        if not result.ok:
            return []

        items: list[Evidence] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 5:
                continue
            unit = parts[0].rstrip(".service")
            if not unit:
                continue
            items.append(
                Evidence(
                    id=self._next_id("svc"),
                    type=EvidenceType.SERVICE,
                    source=self.name,
                    data={"unit": unit, "raw": line},
                    tags=("service", "systemd"),
                )
            )
        return items

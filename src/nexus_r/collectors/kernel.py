"""Kernel collector.

Collects kernel version details for later CVE matching.
"""

from __future__ import annotations

from pathlib import Path

from nexus_r.collectors.base import BaseCollector
from nexus_r.evidence import Evidence, EvidenceType
from nexus_r.utils.shell import run_command


class KernelCollector(BaseCollector):
    """Collects kernel version details."""

    name = "kernel"
    requires_root = False

    def collect(self) -> list[Evidence]:
        items: list[Evidence] = []

        result = run_command(["uname", "-a"], allow=frozenset({"uname"}))
        if result.ok:
            items.append(
                Evidence(
                    id=self._next_id("kern"),
                    type=EvidenceType.SYSTEM,
                    source=self.name,
                    data={"uname_all": result.stdout.strip()},
                    tags=("kernel",),
                )
            )

        version_path = Path("/proc/version")
        if version_path.exists():
            try:
                items.append(
                    Evidence(
                        id=self._next_id("kern"),
                        type=EvidenceType.SYSTEM,
                        source=self.name,
                        data={
                            "proc_version": version_path.read_text(
                                encoding="utf-8", errors="replace"
                            ).strip()
                        },
                        tags=("kernel", "proc"),
                    )
                )
            except OSError:
                pass

        return items

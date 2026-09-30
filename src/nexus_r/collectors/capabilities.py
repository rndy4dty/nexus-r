"""Linux capabilities collector.

Uses `getcap` if available; also inspects running processes via
/proc/<pid>/status. Read-only. Does not judge - that is the rule
engine's job (ADR-001 §3.2).

`getcap -r` output format:

    <path> <cap1>[,<cap2>...]=<flags>

Example:

    /usr/local/bin/py-helper cap_setuid=ep
    /usr/bin/ping cap_net_raw=ep
"""

from __future__ import annotations

from pathlib import Path

from nexus_r.collectors.base import BaseCollector
from nexus_r.evidence import Evidence, EvidenceType
from nexus_r.utils.shell import run_command

SEARCH_ROOTS = ["/usr", "/bin", "/sbin", "/opt", "/usr/local"]

CAP_BITS = {
    "cap_chown": 0,
    "cap_dac_override": 1,
    "cap_dac_read_search": 2,
    "cap_fowner": 3,
    "cap_fsetid": 4,
    "cap_kill": 5,
    "cap_setgid": 6,
    "cap_setuid": 7,
    "cap_setpcap": 8,
    "cap_linux_immutable": 9,
    "cap_net_bind_service": 10,
    "cap_net_broadcast": 11,
    "cap_net_admin": 12,
    "cap_net_raw": 13,
    "cap_ipc_lock": 14,
    "cap_ipc_owner": 15,
    "cap_sys_module": 16,
    "cap_sys_rawio": 17,
    "cap_sys_chroot": 18,
    "cap_sys_ptrace": 19,
    "cap_sys_pacct": 20,
    "cap_sys_admin": 21,
    "cap_sys_boot": 22,
    "cap_sys_nice": 23,
    "cap_sys_resource": 24,
    "cap_sys_time": 25,
    "cap_sys_tty_config": 26,
    "cap_mknod": 27,
    "cap_lease": 28,
    "cap_audit_write": 29,
    "cap_audit_control": 30,
    "cap_setfcap": 31,
}


def _decode_cap_hex(cap_hex: str) -> list[str]:
    """Decode CapEff hex string to a list of capability names."""
    try:
        value = int(cap_hex, 16)
    except ValueError:
        return []
    return [name for name, bit in CAP_BITS.items() if value & (1 << bit)]


def _parse_getcap_line(line: str) -> tuple[str, str] | None:
    """Parse a single getcap output line.

    Returns (path, cap_string) or None if the line is malformed.

    Example:
        "/usr/local/bin/py-helper cap_setuid=ep"
        -> ("/usr/local/bin/py-helper", "cap_setuid=ep")
    """
    line = line.strip()
    if not line or "=" not in line:
        return None
    # Split on the *last* whitespace: everything before is the path,
    # everything after is "<caps>=<flags>".
    parts = line.rsplit(maxsplit=1)
    if len(parts) != 2:
        return None
    path, caps = parts
    if "=" not in caps:
        return None
    return path.strip(), caps.strip()


class CapabilitiesCollector(BaseCollector):
    """Collects file and process capabilities."""

    name = "capabilities"
    requires_root = False

    def collect(self) -> list[Evidence]:
        items: list[Evidence] = []
        items.extend(self._collect_file_caps())
        items.extend(self._collect_proc_caps())
        return items

    def _collect_file_caps(self) -> list[Evidence]:
        items: list[Evidence] = []

        # Skip if getcap is not installed
        probe = run_command(["getcap", "-h"], allow=frozenset({"getcap"}))
        if probe.returncode == 127:
            return items

        seen_paths: set[str] = set()

        for root in SEARCH_ROOTS:
            if not Path(root).exists():
                continue
            result = run_command(
                ["getcap", "-r", root],
                timeout=30.0,
                allow=frozenset({"getcap"}),
            )
            if not result.ok:
                continue
            for raw_line in result.stdout.splitlines():
                parsed = _parse_getcap_line(raw_line)
                if parsed is None:
                    continue
                path, caps = parsed
                if path in seen_paths:
                    continue
                seen_paths.add(path)

                items.append(
                    Evidence(
                        id=self._next_id("cap"),
                        type=EvidenceType.CAPABILITY,
                        source=self.name,
                        data={
                            "path": path,
                            "capabilities": caps,
                            "kind": "file",
                        },
                        tags=("capability", "file"),
                    )
                )
        return items

    def _collect_proc_caps(self) -> list[Evidence]:
        items: list[Evidence] = []
        proc = Path("/proc")
        if not proc.is_dir():
            return items

        for entry in proc.iterdir():
            if not entry.name.isdigit():
                continue
            status = entry / "status"
            try:
                text = status.read_text(encoding="utf-8", errors="replace")
            except (OSError, PermissionError):
                continue

            cap_eff: str | None = None
            name: str | None = None
            for line in text.splitlines():
                if line.startswith("Name:"):
                    name = line.split(":", 1)[1].strip()
                elif line.startswith("CapEff:"):
                    cap_eff = line.split(":", 1)[1].strip()

            if not cap_eff or cap_eff == "0000000000000000":
                continue

            decoded = _decode_cap_hex(cap_eff)
            items.append(
                Evidence(
                    id=self._next_id("cap"),
                    type=EvidenceType.CAPABILITY,
                    source=self.name,
                    data={
                        "pid": int(entry.name),
                        "process_name": name,
                        "cap_eff": cap_eff,
                        "capabilities": decoded,
                        "kind": "process",
                    },
                    tags=("capability", "process"),
                )
            )
        return items

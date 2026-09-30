"""Rule registry."""

from __future__ import annotations

from nexus_r.analysis.rule import Rule
from nexus_r.analysis.rules.capabilities_dangerous import CapabilitiesDangerousRule
from nexus_r.analysis.rules.cron_path_hijack import CronPathHijackRule
from nexus_r.analysis.rules.cron_writable import CronWritableRule
from nexus_r.analysis.rules.docker_socket import DockerSocketRule
from nexus_r.analysis.rules.kernel_outdated import KernelOutdatedRule
from nexus_r.analysis.rules.path_writable import PathWritableRule
from nexus_r.analysis.rules.sudo_dangerous import SudoDangerousRule
from nexus_r.analysis.rules.sudo_nopasswd import SudoNopasswdRule
from nexus_r.analysis.rules.suid_gtfobins import SuidGtfobinsRule
from nexus_r.analysis.rules.writable_sensitive import WritableSensitiveRule


def get_rules() -> list[Rule]:
    """Return instances of all registered rules."""
    return [
        SuidGtfobinsRule(),
        SudoNopasswdRule(),
        SudoDangerousRule(),
        CapabilitiesDangerousRule(),
        CronWritableRule(),
        CronPathHijackRule(),
        WritableSensitiveRule(),
        PathWritableRule(),
        KernelOutdatedRule(),
        DockerSocketRule(),
    ]


__all__ = ["get_rules"]

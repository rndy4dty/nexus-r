"""Rule registry."""

from __future__ import annotations

from nexus_r.analysis.rule import Rule
from nexus_r.analysis.rules.capabilities_dangerous import CapabilitiesDangerousRule
from nexus_r.analysis.rules.sudo_dangerous import SudoDangerousRule
from nexus_r.analysis.rules.sudo_nopasswd import SudoNopasswdRule
from nexus_r.analysis.rules.suid_gtfobins import SuidGtfobinsRule


def get_rules() -> list[Rule]:
    """Return instances of all registered rules."""
    return [
        SuidGtfobinsRule(),
        SudoNopasswdRule(),
        SudoDangerousRule(),
        CapabilitiesDangerousRule(),
    ]


__all__ = ["get_rules"]

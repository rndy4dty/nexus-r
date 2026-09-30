"""Shell command execution helper.

A single, auditable place to run external commands. Collectors must use
this helper rather than calling subprocess directly, so policy can be
enforced centrally in later milestones (ADR-001 §3.4).
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Sequence

DEFAULT_TIMEOUT = 10.0


@dataclass(frozen=True)
class CommandResult:
    """Result of running an external command."""

    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run_command(
    cmd: Sequence[str],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    allow: frozenset[str] | None = None,
) -> CommandResult:
    """Run a command safely and return a CommandResult.

    Args:
        cmd: Command and arguments as a sequence.
        timeout: Timeout in seconds.
        allow: Optional allow-list of executable names. If provided, the
            first element of ``cmd`` must be in the set.

    Returns:
        CommandResult with captured stdout/stderr. Never raises for
        expected failures (missing binary, timeout); returncode carries
        the error signal instead.
    """
    cmd_tuple = tuple(cmd)

    if not cmd_tuple:
        return CommandResult(
            command=(), returncode=2, stdout="", stderr="empty command"
        )

    if allow is not None and cmd_tuple[0] not in allow:
        return CommandResult(
            command=cmd_tuple,
            returncode=126,
            stdout="",
            stderr=f"command not allowed: {cmd_tuple[0]}",
        )

    try:
        completed = subprocess.run(
            cmd_tuple,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return CommandResult(
            command=cmd_tuple,
            returncode=127,
            stdout="",
            stderr=f"command not found: {cmd_tuple[0]}",
        )
    except subprocess.TimeoutExpired:
        return CommandResult(
            command=cmd_tuple,
            returncode=124,
            stdout="",
            stderr=f"timeout after {timeout}s: {' '.join(cmd_tuple)}",
        )

    return CommandResult(
        command=cmd_tuple,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )

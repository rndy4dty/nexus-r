"""Unit tests for the shell helper."""

from __future__ import annotations

from nexus_r.utils.shell import run_command


def test_run_command_empty() -> None:
    result = run_command([])
    assert result.returncode == 2
    assert "empty" in result.stderr


def test_run_command_success() -> None:
    result = run_command(["true"])
    assert result.ok
    assert result.returncode == 0


def test_run_command_failure() -> None:
    result = run_command(["false"])
    assert not result.ok
    assert result.returncode == 1


def test_run_command_not_found() -> None:
    result = run_command(["this-command-does-not-exist-xyz"])
    assert result.returncode == 127
    assert "not found" in result.stderr


def test_run_command_allow_list_rejects() -> None:
    result = run_command(["true"], allow=frozenset({"false"}))
    assert result.returncode == 126
    assert "not allowed" in result.stderr


def test_run_command_allow_list_accepts() -> None:
    result = run_command(["true"], allow=frozenset({"true"}))
    assert result.ok


def test_run_command_captures_stdout() -> None:
    result = run_command(["echo", "hello"])
    assert result.ok
    assert result.stdout.strip() == "hello"


def test_run_command_timeout() -> None:
    result = run_command(["sleep", "2"], timeout=0.1)
    assert result.returncode == 124
    assert "timeout" in result.stderr

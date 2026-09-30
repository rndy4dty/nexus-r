"""Unit tests for cron rules."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from nexus_r.analysis.rules.cron_path_hijack import CronPathHijackRule
from nexus_r.analysis.rules.cron_writable import CronWritableRule
from nexus_r.evidence import Evidence, EvidenceStore, EvidenceType


def _cron_script(ev_id: str, path: str) -> Evidence:
    return Evidence(
        id=ev_id,
        type=EvidenceType.CRON,
        source="cron",
        data={"path": path, "kind": "script", "name": Path(path).name},
    )


def _cron_entry(ev_id: str, path: str, entry: str) -> Evidence:
    return Evidence(
        id=ev_id,
        type=EvidenceType.CRON,
        source="cron",
        data={"path": path, "kind": "entry", "entry": entry, "line": 1},
    )


def _path_entry(ev_id: str, path: str, *, world: bool = False, group: bool = False) -> Evidence:
    return Evidence(
        id=ev_id,
        type=EvidenceType.OTHER,
        source="environment",
        data={
            "kind": "path_entry",
            "path": path,
            "is_dir": True,
            "world_writable": world,
            "group_writable": group,
        },
    )


def test_cron_writable_empty() -> None:
    assert CronWritableRule().evaluate(EvidenceStore()) == []


def test_cron_writable_world(tmp_path: Path) -> None:
    script = tmp_path / "job.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    script.chmod(0o777)

    store = EvidenceStore()
    store.add(_cron_script("cron-0001", str(script)))
    results = CronWritableRule().evaluate(store)
    assert len(results) == 1
    assert "world-writable" in results[0].description


def test_cron_writable_owner(tmp_path: Path) -> None:
    script = tmp_path / "own.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    script.chmod(0o744)  # owner writable, not group, not world

    store = EvidenceStore()
    store.add(_cron_script("cron-0001", str(script)))
    results = CronWritableRule().evaluate(store)
    assert len(results) == 1
    assert "owner-writable" in results[0].description


def test_cron_writable_not_writable(tmp_path: Path) -> None:
    script = tmp_path / "safe.sh"
    script.write_text("#!/bin/sh\necho hi\n")
    script.chmod(0o544)  # read + exec only

    store = EvidenceStore()
    store.add(_cron_script("cron-0001", str(script)))
    assert CronWritableRule().evaluate(store) == []


def test_cron_path_hijack_no_writable_path() -> None:
    store = EvidenceStore()
    store.add(_cron_entry("cron-0001", "/etc/crontab", "* * * * * root myjob arg"))
    assert CronPathHijackRule().evaluate(store) == []


def test_cron_path_hijack_with_writable_path() -> None:
    store = EvidenceStore()
    store.add(_path_entry("env-0001", "/tmp", world=True))
    store.add(_cron_entry("cron-0001", "/etc/crontab", "* * * * * root myjob arg"))
    results = CronPathHijackRule().evaluate(store)
    assert len(results) == 1
    assert "myjob" in results[0].title


def test_cron_path_hijack_ignores_absolute_command() -> None:
    store = EvidenceStore()
    store.add(_path_entry("env-0001", "/tmp", world=True))
    store.add(_cron_entry("cron-0001", "/etc/crontab", "* * * * * root /usr/local/bin/safe"))
    assert CronPathHijackRule().evaluate(store) == []

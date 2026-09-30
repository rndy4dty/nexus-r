"""Unit tests for SshKeysRule."""

from __future__ import annotations

from pathlib import Path

from nexus_r.analysis import Confidence, Severity
from nexus_r.analysis.rules.ssh_keys import SshKeysRule
from nexus_r.evidence import Evidence, EvidenceStore, EvidenceType


def _user_evidence(ev_id: str, home: str) -> Evidence:
    return Evidence(
        id=ev_id,
        type=EvidenceType.USER,
        source="users",
        data={
            "name": "test",
            "uid": 1000,
            "gid": 1000,
            "home": home,
            "shell": "/bin/bash",
            "gecos": "",
        },
    )


def test_empty_store() -> None:
    assert SshKeysRule().evaluate(EvidenceStore()) == []


def test_no_ssh_dir(tmp_path: Path) -> None:
    store = EvidenceStore()
    store.add(_user_evidence("usr-0001", str(tmp_path)))
    assert SshKeysRule().evaluate(store) == []


def test_ssh_dir_no_keys(tmp_path: Path) -> None:
    (tmp_path / ".ssh").mkdir()
    store = EvidenceStore()
    store.add(_user_evidence("usr-0001", str(tmp_path)))
    assert SshKeysRule().evaluate(store) == []


def test_readable_rsa_key(tmp_path: Path) -> None:
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    key = ssh_dir / "id_rsa"
    key.write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n"
    )
    key.chmod(0o600)

    store = EvidenceStore()
    store.add(_user_evidence("usr-0001", str(tmp_path)))
    results = SshKeysRule().evaluate(store)
    assert len(results) == 1
    assert results[0].severity == Severity.HIGH
    assert results[0].confidence == Confidence.MEDIUM
    assert "id_rsa" in results[0].title


def test_public_key_not_flagged(tmp_path: Path) -> None:
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    (ssh_dir / "id_rsa.pub").write_text("ssh-rsa AAAAB3... user@host\n")

    store = EvidenceStore()
    store.add(_user_evidence("usr-0001", str(tmp_path)))
    assert SshKeysRule().evaluate(store) == []


def test_non_key_file_named_identity(tmp_path: Path) -> None:
    ssh_dir = tmp_path / ".ssh"
    ssh_dir.mkdir()
    (ssh_dir / "identity").write_text("not a real key\n")

    store = EvidenceStore()
    store.add(_user_evidence("usr-0001", str(tmp_path)))
    assert SshKeysRule().evaluate(store) == []

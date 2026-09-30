"""Unit tests for CapabilitiesCollector."""

from __future__ import annotations

from nexus_r.collectors.capabilities import (
    CapabilitiesCollector,
    _decode_cap_hex,
)
from nexus_r.evidence import EvidenceType


def test_capabilities_collector_runs() -> None:
    items = CapabilitiesCollector().collect()
    assert isinstance(items, list)


def test_capabilities_collector_types() -> None:
    items = CapabilitiesCollector().collect()
    for item in items:
        assert item.type == EvidenceType.CAPABILITY
        assert item.source == "capabilities"


def test_capabilities_collector_ids_unique() -> None:
    items = CapabilitiesCollector().collect()
    ids = [item.id for item in items]
    assert len(ids) == len(set(ids))
    for i in ids:
        assert i.startswith("cap-")


def test_decode_cap_hex_empty() -> None:
    assert _decode_cap_hex("0000000000000000") == []


def test_decode_cap_hex_setuid() -> None:
    # bit 7 = cap_setuid
    assert "cap_setuid" in _decode_cap_hex("0000000000000080")


def test_decode_cap_hex_sys_admin() -> None:
    # bit 21 = cap_sys_admin
    assert "cap_sys_admin" in _decode_cap_hex("0000000000200000")


def test_decode_cap_hex_invalid() -> None:
    assert _decode_cap_hex("not-a-hex") == []


def test_parse_getcap_line_basic() -> None:
    from nexus_r.collectors.capabilities import _parse_getcap_line

    assert _parse_getcap_line("/usr/local/bin/py-helper cap_setuid=ep") == (
        "/usr/local/bin/py-helper",
        "cap_setuid=ep",
    )


def test_parse_getcap_line_multiple_caps() -> None:
    from nexus_r.collectors.capabilities import _parse_getcap_line

    assert _parse_getcap_line("/usr/bin/foo cap_setuid,cap_setgid=ep") == (
        "/usr/bin/foo",
        "cap_setuid,cap_setgid=ep",
    )


def test_parse_getcap_line_invalid() -> None:
    from nexus_r.collectors.capabilities import _parse_getcap_line

    assert _parse_getcap_line("") is None
    assert _parse_getcap_line("no equals sign here") is None
    assert _parse_getcap_line("only-one-token") is None


def test_parse_getcap_line_path_with_spaces() -> None:
    from nexus_r.collectors.capabilities import _parse_getcap_line

    # rsplit on last whitespace handles paths with spaces correctly
    assert _parse_getcap_line("/opt/my dir/bin/tool cap_setuid=ep") == (
        "/opt/my dir/bin/tool",
        "cap_setuid=ep",
    )

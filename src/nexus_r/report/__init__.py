"""Report writers."""

from nexus_r.report.html_report import build_html_report, write_html_report
from nexus_r.report.json_report import (
    build_report,
    write_json_report,
    write_report,
)

__all__ = [
    "build_html_report",
    "build_report",
    "write_html_report",
    "write_json_report",
    "write_report",
]

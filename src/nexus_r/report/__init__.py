"""Report writers."""

from nexus_r.report.html_report import build_html_report, write_html_report
from nexus_r.report.json_report import (
    build_report,
    write_json_report,
    write_report,
)
from nexus_r.report.markdown_report import (
    build_markdown_report,
    write_markdown_report,
)
from nexus_r.report.sarif_report import build_sarif, write_sarif_report

__all__ = [
    "build_html_report",
    "build_markdown_report",
    "build_report",
    "build_sarif",
    "write_html_report",
    "write_json_report",
    "write_markdown_report",
    "write_report",
    "write_sarif_report",
]

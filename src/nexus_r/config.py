"""Scan configuration for NEXUS-R.

Small, explicit configuration object. No file I/O, no side effects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_OUTPUT_DIR = Path("output")
DEFAULT_FORMAT = "json"


@dataclass(slots=True)
class ScanConfig:
    """Configuration for a single NEXUS-R scan.

    Attributes:
        output_dir: Directory where the report will be written.
        output_format: Report format. Only "json" is supported in V0.1.
        collectors: Optional allow-list of collector names. Empty means all enabled.
        verbose: Whether to print progress information.
    """

    output_dir: Path = field(default_factory=lambda: DEFAULT_OUTPUT_DIR)
    output_format: str = DEFAULT_FORMAT
    collectors: tuple[str, ...] = ()
    verbose: bool = False

    def ensure_output_dir(self) -> Path:
        """Create the output directory if it does not exist and return it."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        return self.output_dir

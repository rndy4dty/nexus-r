"""NEXUS-R command-line interface.

Stub minimal. Command `scan` dan lainnya akan ditambahkan pada step berikutnya.
"""

from __future__ import annotations

import typer

from nexus_r import __version__

app = typer.Typer(
    name="nexus-r",
    help="Evidence-Driven Linux Security Research and Privilege-Escalation Analysis Engine.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def main() -> None:
    """NEXUS-R — Evidence-Driven Linux Security Research Engine."""


@app.command()
def version() -> None:
    """Print the NEXUS-R version."""
    typer.echo(f"nexus-r {__version__}")


if __name__ == "__main__":
    app()

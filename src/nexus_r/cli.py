"""NEXUS-R command-line interface."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from nexus_r import __version__
from nexus_r.config import DEFAULT_FORMAT, DEFAULT_OUTPUT_DIR, ScanConfig
from nexus_r.orchestrator import ScanOrchestrator

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


@app.command()
def scan(
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            "-o",
            help="Directory where the JSON report will be written.",
        ),
    ] = DEFAULT_OUTPUT_DIR,
    fmt: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Report format. Only 'json' is supported in V0.1.",
        ),
    ] = DEFAULT_FORMAT,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Print progress information.",
        ),
    ] = False,
) -> None:
    """Run a NEXUS-R scan against the local Linux system."""
    if fmt != "json":
        typer.secho(
            f"Error: format '{fmt}' is not supported in V0.1 (only 'json').",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)

    config = ScanConfig(
        output_dir=output,
        output_format=fmt,
        verbose=verbose,
    )

    if verbose:
        typer.echo(f"[nexus-r] output_dir = {config.output_dir}")
        typer.echo(f"[nexus-r] format     = {config.output_format}")

    orchestrator = ScanOrchestrator(config=config)
    result = orchestrator.run()

    typer.echo(
        f"Scan complete: {result.collector_count} collectors, "
        f"{result.evidence_count} evidence items."
    )
    if verbose:
        typer.echo(f"[nexus-r] output dir: {config.output_dir.resolve()}")


if __name__ == "__main__":
    app()

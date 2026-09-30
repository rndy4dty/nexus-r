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

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_COLORS = {
    "critical": typer.colors.BRIGHT_RED,
    "high": typer.colors.RED,
    "medium": typer.colors.YELLOW,
    "low": typer.colors.CYAN,
    "info": typer.colors.WHITE,
}


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
        typer.Option("--output", "-o", help="Directory where the JSON report will be written."),
    ] = DEFAULT_OUTPUT_DIR,
    fmt: Annotated[
        str,
        typer.Option("--format", "-f", help="Report format. Only 'json' in V0.1/V0.3."),
    ] = DEFAULT_FORMAT,
    collector: Annotated[
        list[str] | None,
        typer.Option("--collector", "-c", help="Run only the named collector(s). Repeatable."),
    ] = None,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Print progress information."),
    ] = False,
    show_findings: Annotated[
        bool,
        typer.Option("--show-findings/--no-show-findings", help="Print findings to terminal."),
    ] = True,
    show_paths: Annotated[
        bool,
        typer.Option("--show-paths/--no-show-paths", help="Print attack paths to terminal."),
    ] = True,
) -> None:
    """Run a NEXUS-R scan against the local Linux system."""
    if fmt != "json":
        typer.secho(f"Error: format '{fmt}' not supported.", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    config = ScanConfig(
        output_dir=output,
        output_format=fmt,
        collectors=tuple(collector) if collector else (),
        verbose=verbose,
    )

    if verbose:
        typer.echo(f"[nexus-r] output_dir = {config.output_dir}")
        typer.echo(f"[nexus-r] format     = {config.output_format}")
        typer.echo(f"[nexus-r] collectors = {list(config.collectors) or 'all'}")

    orchestrator = ScanOrchestrator(config=config)
    result = orchestrator.run()

    typer.echo("")
    typer.secho("=== NEXUS-R SCAN SUMMARY ===", fg=typer.colors.BRIGHT_WHITE, bold=True)
    typer.echo(f"Collectors run  : {result.collector_count}")
    typer.echo(f"Evidence items  : {result.evidence_count}")
    typer.echo(f"Findings        : {result.finding_count}")
    typer.echo(f"Attack paths    : {result.attack_path_count}")

    if result.findings:
        counts: dict[str, int] = {}
        for f in result.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        typer.echo("")
        typer.echo("Findings by severity:")
        for sev in SEVERITY_ORDER:
            if sev in counts:
                typer.secho(
                    f"  {sev:<10} {counts[sev]}",
                    fg=SEVERITY_COLORS.get(sev, typer.colors.WHITE),
                )

    if show_findings and result.findings:
        typer.echo("")
        typer.secho("=== FINDINGS ===", fg=typer.colors.BRIGHT_WHITE, bold=True)
        for f in result.findings:
            color = SEVERITY_COLORS.get(f.severity.value, typer.colors.WHITE)
            typer.secho(
                f"[{f.severity.value.upper()}/{f.confidence.value.upper()}] "
                f"{f.rule_id} - {f.title}",
                fg=color,
                bold=True,
            )
            if f.description:
                typer.echo(f"    {f.description}")
            typer.echo(f"    evidence: {', '.join(f.evidence_ids) or '-'}")

    if show_paths and result.attack_paths:
        typer.echo("")
        typer.secho(
            "=== ATTACK PATHS ===",
            fg=typer.colors.BRIGHT_RED,
            bold=True,
        )
        for p in result.attack_paths:
            color = SEVERITY_COLORS.get(p.severity.value, typer.colors.WHITE)
            typer.secho(
                f"[{p.severity.value.upper()}/{p.confidence.value.upper()}] "
                f"{p.rule_id} - {p.title}",
                fg=color,
                bold=True,
            )
            if p.narrative:
                typer.echo(f"    {p.narrative}")
            typer.echo(
                f"    entry: {p.entry_point or '?'} → target: {p.target}"
            )
            typer.echo(f"    findings: {', '.join(p.finding_ids) or '-'}")

    typer.echo("")
    typer.echo(f"Report written: {result.report_path}")

    if result.collectors_failed:
        typer.secho("Collectors failed:", fg=typer.colors.YELLOW, err=True)
        for item in result.collectors_failed:
            typer.secho(
                f"  - {item['name']}: {item['error']}",
                fg=typer.colors.YELLOW,
                err=True,
            )


if __name__ == "__main__":
    app()

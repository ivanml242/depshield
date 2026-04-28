"""CLI entry point for depshield."""

import json
import sys

import click
from rich.console import Console

from depshield import __version__


@click.group()
@click.version_option(version=__version__, prog_name="depshield")
def main():
    """depshield -- find malicious dependencies before you install them."""


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format (default: table).",
)
@click.option(
    "--ecosystem",
    type=click.Choice(["npm", "pypi", "auto"]),
    default="auto",
    help="Ecosystem to scan (default: auto-detect).",
)
@click.option(
    "--no-cache",
    is_flag=True,
    default=False,
    help="Disable result caching.",
)
@click.option(
    "--max-depth",
    type=int,
    default=3,
    help="Maximum dependency tree depth (default: 3).",
)
@click.option(
    "--only-direct",
    is_flag=True,
    default=False,
    help="Only analyze direct dependencies.",
)
@click.option(
    "--output",
    "output_file",
    type=click.Path(),
    default=None,
    help="Save JSON report to file.",
)
def scan(path, output_format, ecosystem, no_cache, max_depth, only_direct, output_file):
    """Scan a project directory for malicious dependencies.

    PATH is the project directory to scan (defaults to current directory).
    """
    from depshield.core.scanner import scan_project
    from depshield.scoring.report import save_json

    console = Console()
    console.print(f"[bold]depshield[/bold] v{__version__}\n")

    scores = scan_project(
        path,
        ecosystem=ecosystem,
        use_cache=not no_cache,
        max_depth=max_depth,
        only_direct=only_direct,
        output_format=output_format,
        console=console,
    )

    # Save to file if requested
    if output_file:
        save_json(scores, output_file)
        console.print(f"\n[dim]Report saved to {output_file}[/dim]")

    # Non-zero exit when something looks dangerous
    if any(s.classification == "HIGH_RISK" for s in scores):
        sys.exit(1)


if __name__ == "__main__":
    main()

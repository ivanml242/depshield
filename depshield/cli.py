"""Command-line interface for depshield."""

import click

from depshield import __version__


@click.group()
@click.version_option(version=__version__, prog_name="depshield")
def main():
    """depshield - Detect malicious dependencies before installation.

    Analyzes package.json and/or requirements.txt, resolves the full
    transitive dependency tree, downloads source code, performs static
    analysis looking for malicious behaviors, evaluates package metadata,
    and generates a risk report with per-package scoring.
    """


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
def scan(path, output_format, ecosystem, no_cache, max_depth, only_direct):
    """Scan a project directory for malicious dependencies.

    PATH is the project directory to scan (defaults to current directory).
    """
    click.echo(f"depshield v{__version__}")
    click.echo(f"Scanning: {path}")
    click.echo("Scanner not yet implemented. Coming in PASO 8.")


if __name__ == "__main__":
    main()

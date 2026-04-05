"""Report generator for depshield scan results.

Generates two output formats:
  1. Rich terminal table (colored, human-readable)
  2. JSON (machine-readable, for CI/CD integration)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from depshield.scoring.scorer import PackageScore


# ---------------------------------------------------------------------------
# Color / style helpers
# ---------------------------------------------------------------------------

_CLASSIFICATION_STYLES = {
    "SAFE": "bold green",
    "LOW_RISK": "bold yellow",
    "MEDIUM_RISK": "bold dark_orange",
    "HIGH_RISK": "bold red",
}

_CLASSIFICATION_EMOJI = {
    "SAFE": "✅",
    "LOW_RISK": "⚠️",
    "MEDIUM_RISK": "🟠",
    "HIGH_RISK": "🔴",
}

_SEVERITY_STYLES = {
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "dim",
}


# ---------------------------------------------------------------------------
# Terminal report (rich)
# ---------------------------------------------------------------------------

def print_report(scores: list[PackageScore], *, console: Console | None = None) -> None:
    """Print a rich terminal report of scan results.

    Shows a summary panel followed by a detailed table of all packages,
    with direct dependencies first and findings sorted by severity.
    """
    console = console or Console()

    if not scores:
        console.print("[dim]No packages to report.[/dim]")
        return

    # --- Summary ---
    total = len(scores)
    high_risk = sum(1 for s in scores if s.classification == "HIGH_RISK")
    medium_risk = sum(1 for s in scores if s.classification == "MEDIUM_RISK")
    low_risk = sum(1 for s in scores if s.classification == "LOW_RISK")
    safe = sum(1 for s in scores if s.classification == "SAFE")

    summary = Text()
    summary.append(f"  📦 {total} packages scanned\n")
    if high_risk:
        summary.append(f"  🔴 {high_risk} HIGH RISK\n", style="bold red")
    if medium_risk:
        summary.append(f"  🟠 {medium_risk} MEDIUM RISK\n", style="bold dark_orange")
    if low_risk:
        summary.append(f"  ⚠️  {low_risk} LOW RISK\n", style="bold yellow")
    if safe:
        summary.append(f"  ✅ {safe} SAFE\n", style="bold green")

    console.print(Panel(summary, title="[bold]depshield scan results[/bold]", border_style="blue"))

    # --- Package table ---
    table = Table(
        title="Package Risk Scores",
        show_lines=True,
        title_style="bold",
    )
    table.add_column("Package", style="cyan", no_wrap=True)
    table.add_column("Version", style="dim")
    table.add_column("Type", style="dim")
    table.add_column("Score", justify="right")
    table.add_column("Risk", justify="center")
    table.add_column("Findings", max_width=60)

    for s in scores:
        # Score cell with color
        score_style = _CLASSIFICATION_STYLES.get(s.classification, "")
        score_text = Text(str(s.score), style=score_style)

        # Risk cell
        emoji = _CLASSIFICATION_EMOJI.get(s.classification, "")
        risk_text = Text(f"{emoji} {s.classification}", style=score_style)

        # Dependency type
        dep_type = "direct" if s.is_direct else "transitive"

        # Findings summary
        findings_parts: list[str] = []
        if s.high_count:
            findings_parts.append(f"🔴 {s.high_count} HIGH")
        if s.medium_count:
            findings_parts.append(f"🟡 {s.medium_count} MEDIUM")
        if s.low_count:
            findings_parts.append(f"⚪ {s.low_count} LOW")
        findings_text = ", ".join(findings_parts) if findings_parts else "—"

        table.add_row(s.name, s.version, dep_type, score_text, risk_text, findings_text)

    console.print(table)

    # --- Detailed findings for risky packages ---
    risky = [s for s in scores if s.classification != "SAFE"]
    if risky:
        console.print()
        console.print("[bold]Detailed findings for risky packages:[/bold]")
        console.print()

        for s in risky:
            console.print(
                f"  [cyan]{s.name}@{s.version}[/cyan] "
                f"[{_CLASSIFICATION_STYLES.get(s.classification, '')}]"
                f"({s.classification}, score: {s.score})[/]"
            )
            for f in s.findings:
                sev_style = _SEVERITY_STYLES.get(f.severity, "")
                console.print(
                    f"    [{sev_style}][{f.severity}][/] "
                    f"{f.signal_type}: {f.snippet}"
                )
            console.print()


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------

def to_json(scores: list[PackageScore]) -> dict[str, Any]:
    """Convert scan results to a JSON-serializable dictionary.

    Useful for CI/CD integration, saving results to disk, or piping
    to other tools.
    """
    total = len(scores)
    high_risk = sum(1 for s in scores if s.classification == "HIGH_RISK")
    medium_risk = sum(1 for s in scores if s.classification == "MEDIUM_RISK")

    return {
        "summary": {
            "total_packages": total,
            "high_risk": high_risk,
            "medium_risk": medium_risk,
            "low_risk": sum(1 for s in scores if s.classification == "LOW_RISK"),
            "safe": sum(1 for s in scores if s.classification == "SAFE"),
        },
        "packages": [
            {
                "name": s.name,
                "version": s.version,
                "score": s.score,
                "classification": s.classification,
                "is_direct": s.is_direct,
                "findings": [
                    {
                        "signal_type": f.signal_type,
                        "severity": f.severity,
                        "file": f.file,
                        "line": f.line,
                        "snippet": f.snippet,
                    }
                    for f in s.findings
                ],
            }
            for s in scores
        ],
    }


def save_json(scores: list[PackageScore], path: str | Path) -> Path:
    """Save scan results as a JSON file."""
    path = Path(path)
    data = to_json(scores)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path

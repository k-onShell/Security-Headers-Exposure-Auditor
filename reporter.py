"""
Vulnerability reporting engine.
Categorizes findings by severity and exports to JSON, standalone dark-themed HTML dashboard, and Rich terminal tables.
"""

import json
from datetime import datetime
from typing import Dict, List, Any
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from config import SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO


class Reporter:
    """Handles report generation in JSON, HTML dashboard, and Rich CLI output formats."""

    def __init__(self, target_url: str, findings: List[Dict[str, Any]]):
        self.target_url = target_url
        self.findings = findings
        self.timestamp = datetime.utcnow().isoformat() + "Z"

    def get_summary_counts(self) -> Dict[str, int]:
        counts = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 0, SEVERITY_LOW: 0, SEVERITY_INFO: 0}
        for f in self.findings:
            sev = f.get("severity", SEVERITY_INFO)
            if sev in counts:
                counts[sev] += 1
        return counts

    def export_json(self, output_path: str) -> None:
        """Export findings to a structured JSON file."""
        report_data = {
            "target": self.target_url,
            "scan_timestamp": self.timestamp,
            "summary": self.get_summary_counts(),
            "total_findings": len(self.findings),
            "findings": self.findings
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)

    def export_html(self, output_path: str) -> None:
        """Export a standalone dark-themed HTML security dashboard report."""
        counts = self.get_summary_counts()

        findings_html = ""
        for f in self.findings:
            sev = f.get("severity", "Info")
            badge_class = f"badge-{sev.lower()}"
            findings_html += f"""
            <div class="finding-card {sev.lower()}">
                <div class="finding-header">
                    <span class="badge {badge_class}">{sev}</span>
                    <h3>{f.get('title')}</h3>
                </div>
                <p><strong>Category:</strong> {f.get('category')}</p>
                <p><strong>Target Item / Header:</strong> <code>{f.get('header')}</code></p>
                <p><strong>Description:</strong> {f.get('description')}</p>
                <p><strong>Current Value:</strong> <code>{f.get('current_value')}</code></p>
                <div class="recommendation">
                    <strong>Remediation:</strong> {f.get('recommendation')}
                </div>
            </div>
            """

        if not findings_html:
            findings_html = "<div class='no-findings'>No security issues or exposures detected! Excellent job.</div>"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - {self.target_url}</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-color: #f8fafc;
            --text-muted: #94a3b8;
            --border-color: #334155;
            --high: #ef4444;
            --medium: #f59e0b;
            --low: #3b82f6;
            --info: #10b981;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 2rem;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        h1 {{
            margin: 0 0 0.5rem 0;
            font-size: 2rem;
            color: #38bdf8;
        }}
        .meta {{
            color: var(--text-muted);
            font-size: 0.95rem;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2.5rem;
        }}
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
        }}
        .stat-card.high {{ border-left: 5px solid var(--high); }}
        .stat-card.medium {{ border-left: 5px solid var(--medium); }}
        .stat-card.low {{ border-left: 5px solid var(--low); }}
        .stat-card.info {{ border-left: 5px solid var(--info); }}
        .stat-number {{
            font-size: 2.5rem;
            font-weight: bold;
            margin-top: 0.5rem;
        }}
        .finding-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        .finding-card.high {{ border-left: 5px solid var(--high); }}
        .finding-card.medium {{ border-left: 5px solid var(--medium); }}
        .finding-card.low {{ border-left: 5px solid var(--low); }}
        .finding-card.info {{ border-left: 5px solid var(--info); }}
        .finding-header {{
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 0.75rem;
        }}
        .finding-header h3 {{
            margin: 0;
            font-size: 1.25rem;
        }}
        .badge {{
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .badge-high {{ background-color: rgba(239, 68, 68, 0.2); color: #f87171; }}
        .badge-medium {{ background-color: rgba(245, 158, 11, 0.2); color: #fbbf24; }}
        .badge-low {{ background-color: rgba(59, 130, 246, 0.2); color: #60a5fa; }}
        .badge-info {{ background-color: rgba(16, 185, 129, 0.2); color: #34d399; }}
        code {{
            background: #0f172a;
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-family: monospace;
            font-size: 0.9rem;
            color: #38bdf8;
        }}
        .recommendation {{
            background: rgba(56, 189, 248, 0.1);
            border-left: 3px solid #38bdf8;
            padding: 0.75rem 1rem;
            margin-top: 1rem;
            border-radius: 0 4px 4px 0;
        }}
        .no-findings {{
            text-align: center;
            padding: 3rem;
            background: var(--card-bg);
            border-radius: 8px;
            color: var(--info);
            font-size: 1.2rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Headers &amp; Exposure Audit Report</h1>
            <div class="meta">
                Target: <strong>{self.target_url}</strong> &bull; Generated: {self.timestamp}
            </div>
        </header>

        <div class="stats-grid">
            <div class="stat-card high">
                <div>High Severity</div>
                <div class="stat-number" style="color: var(--high);">{counts[SEVERITY_HIGH]}</div>
            </div>
            <div class="stat-card medium">
                <div>Medium Severity</div>
                <div class="stat-number" style="color: var(--medium);">{counts[SEVERITY_MEDIUM]}</div>
            </div>
            <div class="stat-card low">
                <div>Low Severity</div>
                <div class="stat-number" style="color: var(--low);">{counts[SEVERITY_LOW]}</div>
            </div>
            <div class="stat-card info">
                <div>Info / Disclosures</div>
                <div class="stat-number" style="color: var(--info);">{counts[SEVERITY_INFO]}</div>
            </div>
        </div>

        <h2>Audit Findings ({len(self.findings)})</h2>
        {findings_html}
    </div>
</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

    def print_cli_summary(self, console: Console) -> None:
        """Print rich severity-colored tables and summary panel to the console."""
        counts = self.get_summary_counts()

        summary_text = (
            f"[bold]Target:[/bold] {self.target_url}\n"
            f"[red]■ High:[/red] {counts[SEVERITY_HIGH]}  "
            f"[yellow]■ Medium:[/yellow] {counts[SEVERITY_MEDIUM]}  "
            f"[blue]■ Low:[/blue] {counts[SEVERITY_LOW]}  "
            f"[green]■ Info:[/green] {counts[SEVERITY_INFO]}"
        )
        console.print(Panel(summary_text, title="Security Audit Summary", expand=False))

        if not self.findings:
            console.print("[green]No vulnerabilities or exposure issues detected![/green]")
            return

        table = Table(title="Vulnerability & Exposure Findings", show_lines=True, expand=True)
        table.add_column("Severity", justify="center", style="bold", width=10)
        table.add_column("Category", style="cyan", width=22)
        table.add_column("Item / Header", style="magenta", width=25)
        table.add_column("Title / Description", style="white")

        # Sort findings by severity priority
        severity_order = {SEVERITY_HIGH: 0, SEVERITY_MEDIUM: 1, SEVERITY_LOW: 2, SEVERITY_INFO: 3}
        sorted_findings = sorted(self.findings, key=lambda x: severity_order.get(x.get("severity"), 4))

        for f in sorted_findings:
            sev = f.get("severity", SEVERITY_INFO)
            if sev == SEVERITY_HIGH:
                sev_styled = "[red]HIGH[/red]"
            elif sev == SEVERITY_MEDIUM:
                sev_styled = "[yellow]MEDIUM[/yellow]"
            elif sev == SEVERITY_LOW:
                sev_styled = "[blue]LOW[/blue]"
            else:
                sev_styled = "[green]INFO[/green]"

            table.add_row(
                sev_styled,
                f.get("category", ""),
                f.get("header", ""),
                f"[bold]{f.get('title')}[/bold]\n[dim]{f.get('description')}[/dim]"
            )

        console.print(table)

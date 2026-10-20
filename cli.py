"""
Command-line interface built with Typer and Rich.
Orchestrates header auditing, active CORS testing, and sensitive exposure scanning.
"""

import asyncio
import sys
from typing import Optional
import httpx
import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from config import DEFAULT_TIMEOUT, MAX_CONCURRENCY, USER_AGENT
from headers_auditor import HeadersAuditor
from cors_tester import CorsTester
from exposure_scanner import ExposureScanner
from reporter import Reporter

app = typer.Typer(
    name="auditor",
    help="Security Headers & Exposure Auditor - Professional CLI for HTTP security auditing, CORS testing, and sensitive file discovery.",
    add_completion=False,
)
console = Console()


async def audit_single_target(
    url: str,
    verify_ssl: bool,
    timeout: float,
    concurrency: int,
    output_json: Optional[str] = None,
    output_html: Optional[str] = None,
) -> int:
    """Run full security audit on a single URL target."""
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    console.print(f"\n[bold blue][*][/bold blue] Starting security audit for target: [cyan]{url}[/cyan]")

    headers = {"User-Agent": USER_AGENT}
    transport = httpx.AsyncHTTPTransport(retries=2)

    async with httpx.AsyncClient(
        headers=headers,
        verify=verify_ssl,
        timeout=timeout,
        transport=transport,
        follow_redirects=True,
    ) as client:
        # 1. Fetch initial response for headers inspection
        with console.status("[bold green]Inspecting HTTP security headers..."):
            try:
                response = await client.get(url)
                headers_auditor = HeadersAuditor(dict(response.headers), url)
                header_findings = headers_auditor.audit()
            except Exception as e:
                console.print(f"[bold red][!] Error connecting to target {url}: {e}[/bold red]")
                return 1

        # 2. Run Active CORS testing
        with console.status("[bold green]Performing active CORS misconfiguration tests..."):
            cors_tester = CorsTester(client, url)
            cors_findings = await cors_tester.test_cors()

        # 3. Run Sensitive Exposure Discovery with progress bar
        exposure_findings = []
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("[green]Scanning for exposed sensitive files & backups...", total=None)
            exposure_scanner = ExposureScanner(client, url)
            exposure_findings = await exposure_scanner.scan(semaphore_limit=concurrency)
            progress.update(task, completed=True)

        all_findings = header_findings + cors_findings + exposure_findings

        # 4. Generate Reports
        reporter = Reporter(url, all_findings)
        reporter.print_cli_summary(console)

        if output_json:
            reporter.export_json(output_json)
            console.print(f"[green][+] JSON report saved to: {output_json}[/green]")

        if output_html:
            reporter.export_html(output_html)
            console.print(f"[green][+] HTML dashboard report saved to: {output_html}[/green]")

        # Return non-zero exit code if High severity vulnerabilities were found
        high_count = reporter.get_summary_counts().get("High", 0)
        return 1 if high_count > 0 else 0


@app.command()
def main(
    target: Optional[str] = typer.Option(
        None, "--target", "-t", help="Single target URL to audit (e.g. https://example.com)"
    ),
    target_list: Optional[str] = typer.Option(
        None, "--list", "-l", help="Path to a text file containing a list of target URLs (one per line)"
    ),
    verify_ssl: bool = typer.Option(
        True, "--verify-ssl/--no-verify-ssl", help="Enable or disable SSL/TLS certificate verification"
    ),
    timeout: float = typer.Option(
        DEFAULT_TIMEOUT, "--timeout", help="HTTP request timeout in seconds"
    ),
    concurrency: int = typer.Option(
        MAX_CONCURRENCY, "--concurrency", "-c", help="Maximum concurrent requests for exposure scanner"
    ),
    output_json: Optional[str] = typer.Option(
        None, "--json", "-j", help="Path to export structured JSON report"
    ),
    output_html: Optional[str] = typer.Option(
        None, "--html", help="Path to export standalone dark-themed HTML dashboard report"
    ),
):
    """
    Security Headers & Exposure Auditor CLI
    """
    if not target and not target_list:
        console.print("[bold red][!] Error: You must specify either --target (-t) or --list (-l).[/bold red]")
        raise typer.Exit(code=1)

    targets = []
    if target:
        targets.append(target)

    if target_list:
        try:
            with open(target_list, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        targets.append(stripped)
        except Exception as e:
            console.print(f"[bold red][!] Error reading target list file '{target_list}': {e}[/bold red]")
            raise typer.Exit(code=1)

    if not targets:
        console.print("[bold red][!] Error: No valid targets found to audit.[/bold red]")
        raise typer.Exit(code=1)

    exit_code = 0
    for idx, t in enumerate(targets):
        if len(targets) > 1:
            console.print(f"\n[bold magenta]=== Target {idx+1}/{len(targets)}: {t} ===[/bold magenta]")

        code = asyncio.run(
            audit_single_target(
                url=t,
                verify_ssl=verify_ssl,
                timeout=timeout,
                concurrency=concurrency,
                output_json=output_json if len(targets) == 1 else f"audit_report_{idx+1}.json",
                output_html=output_html if len(targets) == 1 else f"audit_report_{idx+1}.html",
            )
        )
        if code != 0:
            exit_code = code

    raise typer.Exit(code=exit_code)


if __name__ == "__main__":
    app()

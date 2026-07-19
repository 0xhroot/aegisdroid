"""AegisDroid CLI - Main application entry point."""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from aegisdroid import __version__
from aegisdroid.core.config import AegisConfig, load_config
from aegisdroid.core.domain import Severity

console = Console()
app = typer.Typer(
    name="aegis",
    help="[bold green]AegisDroid[/bold green] - Advanced Android Security, Threat Hunting & Digital Forensics Framework",
    rich_markup_mode="rich",
    no_args_is_help=True,
    add_completion=False,
)

CONFIG_OPTION = typer.Option(None, "--config", "-c", help="Path to config file")
VERBOSE_OPTION = typer.Option(False, "--verbose", "-v", help="Verbose output")
SERIAL_OPTION = typer.Option(None, "--serial", "-s", help="Device serial number")


def _get_config(config_path: str | None) -> AegisConfig:
    return load_config(config_path)


def _print_banner() -> None:
    banner = Text()
    banner.append("    ___  ________  _______   ____  ________  ___\n", style="bold green")
    banner.append("   /   |/_  __/ / / /   | |  / _ \\/ __/ __ \\/ _ \\\n", style="bold green")
    banner.append("  / /| | / / / /_/ / /| | | / /_/ / /_/ /_/ /  __/\n", style="bold green")
    banner.append(" / ___ |/ / / __  / ___ | |/ _, _/ __/ _, _/ /\n", style="bold green")
    banner.append("/_/  |_/_/ /_/ /_/_/  |_|____/_/ /_/ /_/ |_|/\n", style="bold green")
    banner.append(f"\n  v{__version__} - Advanced Android Security Framework\n", style="dim")
    console.print(Panel(banner, border_style="green", expand=False))


def _severity_color(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "bold yellow",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
        Severity.NONE: "dim",
    }.get(severity, "white")


def _run_async(coro):  # type: ignore
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, coro).result()
        else:
            return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


# ──────────────────────────────────────────────────
#  aegis scan
# ──────────────────────────────────────────────────


@app.command()
def scan(
    package: str | None = typer.Argument(None, help="Package name to scan (empty for device scan)"),
    scan_type: str = typer.Option("quick", "--type", "-t", help="Scan type: quick, full, deep"),
    config: str | None = CONFIG_OPTION,
    verbose: bool = VERBOSE_OPTION,
    serial: str | None = SERIAL_OPTION,
    output: str | None = typer.Option(None, "--output", "-o", help="Output file"),
    format: str = typer.Option(
        "markdown", "--format", "-f", help="Report format: markdown, json, html, sarif"
    ),
) -> None:
    """Run a security scan on a connected device or specific package."""
    _print_banner()
    cfg = _get_config(config)
    if verbose:
        cfg.verbose = True

    from aegisdroid.scanner.engine import Scanner

    async def _run() -> None:
        scanner = Scanner(cfg)
        if serial:
            scanner.adb._serial = serial

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"[green]Scanning{' ' + package if package else ' device'}...",
                total=None,
            )

            if scan_type == "quick":
                result = await scanner.quick_scan(package or "")
            elif scan_type == "full":
                result = await scanner.full_scan(package or "")
            elif scan_type == "deep":
                result = await scanner.deep_scan(package or "")
            else:
                result = await scanner.quick_scan(package or "")

            progress.update(task, description="[green]Scan complete!")

        _display_scan_result(result)

        if output or format != "markdown":
            from aegisdroid.reports.generator import ReportGenerator

            generator = ReportGenerator()
            path = await generator.generate(result, format=format, output_path=output or "")
            console.print(f"\n[green]Report saved to:[/green] {path}")

    _run_async(_run())


def _display_scan_result(result):  # type: ignore
    """Display scan results in a beautiful Rich table."""
    console.print()

    score = result.threat_confidence_score
    score_color = "bold red" if score >= 0.7 else "bold yellow" if score >= 0.4 else "green"
    console.print(
        Panel(
            f"[{score_color}]Threat Confidence Score: {score:.0%}[/{score_color}]\n"
            f"Findings: {len(result.findings)} | "
            f"Critical: {result.total_critical} | High: {result.total_high}",
            title="[bold]Scan Summary[/bold]",
            border_style="green" if score < 0.3 else "yellow" if score < 0.6 else "red",
        )
    )

    if result.findings:
        table = Table(
            title="Findings",
            box=box.ROUNDED,
            show_lines=True,
            title_style="bold",
        )
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Category", width=20)
        table.add_column("Title", min_width=30)
        table.add_column("Confidence", width=12)

        sorted_findings = sorted(
            result.findings,
            key=lambda f: {
                Severity.CRITICAL: 0,
                Severity.HIGH: 1,
                Severity.MEDIUM: 2,
                Severity.LOW: 3,
                Severity.INFO: 4,
            }.get(f.severity, 5),
        )

        for finding in sorted_findings:
            sev_color = _severity_color(finding.severity)
            table.add_row(
                f"[{sev_color}]{finding.severity.value.upper()}[/{sev_color}]",
                finding.category.value.replace("_", " ").title(),
                finding.title,
                f"{finding.confidence:.0%}",
            )

        console.print(table)

        for finding in sorted_findings[:5]:
            if finding.evidence:
                console.print(f"\n[bold]{finding.title}[/bold]")
                for e in finding.evidence[:3]:
                    console.print(f"  [dim]•[/dim] {e.description}")
                if finding.mitigation:
                    console.print(f"  [yellow]Mitigation:[/yellow] {finding.mitigation}")
    else:
        console.print("[green]No findings detected.[/green]")

    if result.error:
        console.print(f"\n[red]Error: {result.error}[/red]")


# ──────────────────────────────────────────────────
#  aegis deep-scan
# ──────────────────────────────────────────────────


@app.command("deep-scan")
def deep_scan(
    package: str | None = typer.Argument(None, help="Package name"),
    config: str | None = CONFIG_OPTION,
    verbose: bool = VERBOSE_OPTION,
    serial: str | None = SERIAL_OPTION,
    output: str | None = typer.Option(None, "--output", "-o"),
) -> None:
    """Run a comprehensive deep security scan."""
    scan(
        package=package,
        scan_type="deep",
        config=config,
        verbose=verbose,
        serial=serial,
        output=output,
        format="markdown",
    )


# ──────────────────────────────────────────────────
#  aegis apk
# ──────────────────────────────────────────────────


@app.command()
def apk(
    path: str = typer.Argument(..., help="Path to APK file or package name"),
    config: str | None = CONFIG_OPTION,
    verbose: bool = VERBOSE_OPTION,
) -> None:
    """Analyze an APK file statically."""
    _print_banner()

    async def _run() -> None:
        from aegisdroid.apk.analyzer import APKAnalyzer

        analyzer = APKAnalyzer()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("[green]Analyzing APK...", total=None)
            if path.endswith(".apk") and Path(path).exists():
                app_info = await analyzer.analyze(path)
            else:
                from aegisdroid.adb.adapter import ADBAdapter

                adb = ADBAdapter(_get_config(config).adb)
                connected = await adb.connect()
                if not connected:
                    console.print("[red]No device connected[/red]")
                    return
                apk_path = await adb.get_package_path(path)
                if not apk_path:
                    console.print(f"[red]Package not found: {path}[/red]")
                    return
                local = f"/tmp/_aegis_{path.replace('.', '_')}.apk"
                await adb.pull(apk_path, local)
                app_info = await analyzer.analyze(local)
            progress.update(task, description="[green]Analysis complete!")

        table = Table(title=f"APK Analysis: {app_info.package_name}", box=box.ROUNDED)
        table.add_column("Property", style="bold")
        table.add_column("Value")

        table.add_row("Package", app_info.package_name)
        table.add_row("Version", app_info.version_name)
        table.add_row("Target SDK", str(app_info.target_sdk))
        table.add_row("Min SDK", str(app_info.min_sdk))
        table.add_row("Debuggable", "Yes" if app_info.is_debuggable else "No")
        table.add_row("Backup Allowed", "Yes" if app_info.is_backup_allowed else "No")
        table.add_row("Has Native Code", "Yes" if app_info.has_native_code else "No")
        table.add_row("Dynamic Code Loading", "Yes" if app_info.has_dynamic_code else "No")
        table.add_row(
            "Risk Rating",
            f"[{_severity_color(app_info.risk_rating)}]{app_info.risk_rating.value.upper()}[/{_severity_color(app_info.risk_rating)}]",
        )
        table.add_row("Total Permissions", str(app_info.total_permissions))
        table.add_row("Dangerous Permissions", str(len(app_info.dangerous_permissions)))
        table.add_row("Exported Components", str(len(app_info.exported_components)))
        table.add_row("Open Components", str(len(app_info.open_components)))
        table.add_row("Trackers", ", ".join(app_info.trackers) if app_info.trackers else "None")

        if app_info.certificate:
            table.add_row("Certificate Subject", app_info.certificate.subject[:60])
            table.add_row("Self-Signed", "Yes" if app_info.certificate.is_self_signed else "No")

        console.print(table)

        if app_info.permissions:
            perm_table = Table(title="Permissions", box=box.SIMPLE)
            perm_table.add_column("Permission", min_width=40)
            perm_table.add_column("Dangerous", width=10)

            for p in sorted(app_info.permissions, key=lambda x: x.name):
                danger = "[red]Yes[/red]" if p.is_risky else "No"
                perm_table.add_row(p.name, danger)

            console.print(perm_table)

        if app_info.exported_components:
            comp_table = Table(title="Exported Components", box=box.SIMPLE)
            comp_table.add_column("Name", min_width=40)
            comp_table.add_column("Type", width=12)
            comp_table.add_column("Protected", width=10)

            for c in app_info.exported_components:
                prot = "Yes" if c.is_protected else "[red]No[/red]"
                comp_table.add_row(c.name, c.component_type.value, prot)

            console.print(comp_table)

    _run_async(_run())


# ──────────────────────────────────────────────────
#  aegis hunt
# ──────────────────────────────────────────────────


@app.command()
def hunt(
    query: str = typer.Argument(
        ..., help="Hunt query (e.g., 'camera AND internet AND accessibility')"
    ),
    config: str | None = CONFIG_OPTION,
    verbose: bool = VERBOSE_OPTION,
    serial: str | None = SERIAL_OPTION,
) -> None:
    """Interactive threat hunting with queries."""
    _print_banner()

    async def _run() -> None:
        from aegisdroid.scanner.engine import Scanner

        scanner = Scanner(_get_config(config))
        if serial:
            scanner.adb._serial = serial

        connected = await scanner.adb.connect()
        if not connected:
            console.print("[red]No device connected[/red]")
            return

        console.print(f"[yellow]Hunting:[/yellow] {query}")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("[green]Running hunt...", total=None)
            result = await scanner.full_scan()
            progress.update(task, description="[green]Hunt complete!")

        query_lower = query.lower()
        matched = []
        for f in result.findings:
            searchable = f"{f.title} {f.description} {f.category.value}".lower()
            terms = [
                t.strip() for t in query_lower.replace(" and ", " ").replace("or", " ").split()
            ]
            if all(term in searchable for term in terms):
                matched.append(f)

        if matched:
            console.print(f"\n[green]Found {len(matched)} matching findings:[/green]")
            for f in matched:
                console.print(
                    f"  [{_severity_color(f.severity)}]{f.severity.value.upper()}[/{_severity_color(f.severity)}] {f.title}"
                )
        else:
            console.print("[yellow]No matching findings for this query.[/yellow]")

    _run_async(_run())


# ──────────────────────────────────────────────────
#  aegis diff
# ──────────────────────────────────────────────────


@app.command()
def diff(
    scan_id_1: str = typer.Argument(..., help="First scan ID"),
    scan_id_2: str = typer.Argument(..., help="Second scan ID"),
    config: str | None = CONFIG_OPTION,
) -> None:
    """Compare two scans and show differences."""
    _print_banner()

    async def _run() -> None:
        from aegisdroid.database.store import Database
        from aegisdroid.diff.engine import DiffEngine

        db = Database()
        await db.initialize()

        old = await db.get_scan(scan_id_1)
        new = await db.get_scan(scan_id_2)

        if not old or not new:
            console.print("[red]Scan(s) not found[/red]")
            return

        engine = DiffEngine()
        result = engine.diff(old, new)
        output = engine.format_diff(result)
        console.print(output)

    _run_async(_run())


# ──────────────────────────────────────────────────
#  aegis monitor
# ──────────────────────────────────────────────────


@app.command()
def monitor(
    interval: float = typer.Option(5.0, "--interval", "-i", help="Poll interval in seconds"),
    config: str | None = CONFIG_OPTION,
    serial: str | None = SERIAL_OPTION,
) -> None:
    """Start live device monitoring."""
    _print_banner()
    console.print("[yellow]Starting live monitor... Press Ctrl+C to stop.[/yellow]\n")

    async def _run() -> None:
        from aegisdroid.adb.adapter import ADBAdapter
        from aegisdroid.live.monitor import LiveMonitor

        cfg = _get_config(config)
        cfg.live_monitor.poll_interval = interval
        adb = ADBAdapter(cfg.adb)
        if serial:
            adb._serial = serial

        connected = await adb.connect()
        if not connected:
            console.print("[red]No device connected[/red]")
            return

        monitor_inst = LiveMonitor(adb, cfg.live_monitor)

        from aegisdroid.core.events import Event, event_bus

        async def on_alert(event: Event) -> None:
            if event.name != "live.monitor.tick":
                console.print(f"[bold yellow]ALERT:[/bold yellow] {event.name}: {event.data}")

        event_bus.subscribe("*", on_alert)

        try:
            await monitor_inst.start()
        except KeyboardInterrupt:
            await monitor_inst.stop()
            console.print("\n[yellow]Monitor stopped.[/yellow]")

    _run_async(_run())


# ──────────────────────────────────────────────────
#  aegis timeline
# ──────────────────────────────────────────────────


@app.command()
def timeline(
    config: str | None = CONFIG_OPTION,
    serial: str | None = SERIAL_OPTION,
    limit: int = typer.Option(50, "--limit", "-l", help="Max events to show"),
) -> None:
    """Generate forensic timeline."""
    _print_banner()

    async def _run() -> None:
        from aegisdroid.adb.adapter import ADBAdapter
        from aegisdroid.timeline.engine import TimelineEngine

        adb = ADBAdapter(_get_config(config).adb)
        if serial:
            adb._serial = serial

        connected = await adb.connect()
        if not connected:
            console.print("[red]No device connected[/red]")
            return

        engine = TimelineEngine(adb)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("[green]Generating timeline...", total=None)
            events = await engine.generate_timeline()
            progress.update(task, description="[green]Timeline generated!")

        table = Table(title="Forensic Timeline", box=box.ROUNDED)
        table.add_column("Timestamp", width=20)
        table.add_column("Category", width=15)
        table.add_column("Title", min_width=30)
        table.add_column("Severity", width=10)

        for event in events[:limit]:
            sev_color = _severity_color(event.severity)
            table.add_row(
                event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                event.category,
                event.title,
                f"[{sev_color}]{event.severity.value}[/{sev_color}]",
            )

        console.print(table)

    _run_async(_run())


# ──────────────────────────────────────────────────
#  aegis yara
# ──────────────────────────────────────────────────


@app.command()
def yara(
    path: str = typer.Argument(..., help="File, directory, or APK to scan"),
    rules: str | None = typer.Option(None, "--rules", "-r", help="Rules directory"),
    config: str | None = CONFIG_OPTION,
) -> None:
    """Scan files with YARA rules."""
    _print_banner()

    async def _run() -> None:
        from aegisdroid.yara.engine import YaraEngine

        engine = YaraEngine(rules or "")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("[green]Scanning with YARA...", total=None)

            target = Path(path)
            if target.is_file():
                if path.endswith(".apk"):
                    matches = await engine.scan_apk(path)
                else:
                    matches = await engine.scan_file(path)
            elif target.is_dir():
                matches = await engine.scan_directory(path)
            else:
                console.print(f"[red]Path not found: {path}[/red]")
                return

            progress.update(task, description="[green]YARA scan complete!")

        if matches:
            table = Table(title="YARA Matches", box=box.ROUNDED)
            table.add_column("Rule", style="bold")
            table.add_column("File")
            table.add_column("Description")
            table.add_column("Tags")

            for m in matches:
                table.add_row(
                    m.rule_name,
                    m.file_path,
                    m.description[:50] if m.description else "",
                    ", ".join(m.tags) if m.tags else "",
                )
            console.print(table)
        else:
            console.print("[green]No YARA matches found.[/green]")

    _run_async(_run())


# ──────────────────────────────────────────────────
#  aegis report
# ──────────────────────────────────────────────────


@app.command()
def report(
    scan_id: str | None = typer.Argument(None, help="Scan ID to report on"),
    format: str = typer.Option(
        "markdown", "--format", "-f", help="Format: markdown, json, html, sarif"
    ),
    output: str | None = typer.Option(None, "--output", "-o", help="Output path"),
    config: str | None = CONFIG_OPTION,
) -> None:
    """Generate reports from scan results."""
    _print_banner()

    async def _run() -> None:
        from aegisdroid.database.store import Database
        from aegisdroid.reports.generator import ReportGenerator

        db = Database()
        await db.initialize()

        if scan_id:
            result = await db.get_scan(scan_id)
            if not result:
                console.print(f"[red]Scan not found: {scan_id}[/red]")
                return
        else:
            scans = await db.list_scans(1)
            if not scans:
                console.print("[yellow]No scans found. Run a scan first.[/yellow]")
                return
            result = scans[0]

        generator = ReportGenerator()
        path = await generator.generate(result, format=format, output_path=output or "")
        console.print(f"[green]Report generated:[/green] {path}")

    _run_async(_run())


# ──────────────────────────────────────────────────
#  aegis search
# ──────────────────────────────────────────────────


@app.command()
def search(
    query: str = typer.Argument(..., help="Search query"),
    config: str | None = CONFIG_OPTION,
) -> None:
    """Global fuzzy search across scans and findings."""
    _print_banner()

    async def _run() -> None:
        from aegisdroid.database.store import Database
        from aegisdroid.search.engine import SearchEngine

        db = Database()
        await db.initialize()

        search_engine = SearchEngine()
        scans = await db.list_scans(100)
        for scan in scans:
            search_engine.index_scan(scan)

        results = search_engine.search(query)

        if results:
            table = Table(title=f"Search Results: {query}", box=box.ROUNDED)
            table.add_column("Type", width=10)
            table.add_column("Score", width=8)
            table.add_column("Details", min_width=40)

            for r in results:
                if r["type"] == "finding":
                    finding = r["data"]
                    table.add_row(
                        "Finding",
                        f"{r['score']:.2f}",
                        f"[{_severity_color(finding.severity)}]{finding.severity.value.upper()}[/{_severity_color(finding.severity)}] {finding.title}",
                    )
                else:
                    table.add_row(r["type"], f"{r['score']:.2f}", str(r["data"])[:80])

            console.print(table)
        else:
            console.print("[yellow]No results found.[/yellow]")

    _run_async(_run())


# ──────────────────────────────────────────────────
#  aegis plugins
# ──────────────────────────────────────────────────


@app.command()
def plugins(
    action: str = typer.Argument("list", help="Action: list, load"),
    name: str | None = typer.Argument(None, help="Plugin name"),
    config: str | None = CONFIG_OPTION,
) -> None:
    """Manage AegisDroid plugins."""
    _print_banner()

    async def _run() -> None:
        from aegisdroid.plugins.sdk import PluginSDK

        cfg = _get_config(config)
        sdk = PluginSDK(cfg.plugin.effective_directory)

        if action == "list":
            discovered = await sdk.discover_plugins()
            if discovered:
                table = Table(title="Plugins", box=box.ROUNDED)
                table.add_column("Name", style="bold")
                table.add_column("Version")
                table.add_column("Description")
                for meta in discovered:
                    table.add_row(meta.name, meta.version, meta.description)
                console.print(table)
            else:
                console.print("[yellow]No plugins found.[/yellow]")

        elif action == "load" and name:
            plugin = await sdk.load_plugin(name)
            if plugin:
                console.print(f"[green]Plugin loaded:[/green] {name}")
            else:
                console.print(f"[red]Failed to load plugin:[/red] {name}")

    _run_async(_run())


# ──────────────────────────────────────────────────
#  aegis doctor
# ──────────────────────────────────────────────────


@app.command()
def doctor(
    config: str | None = CONFIG_OPTION,
) -> None:
    """Check system requirements and connectivity."""
    _print_banner()

    table = Table(title="System Check", box=box.ROUNDED)
    table.add_column("Component", style="bold")
    table.add_column("Status")
    table.add_column("Details")

    import shutil

    adb_path = shutil.which("adb")
    table.add_row(
        "ADB",
        "[green]Found[/green]" if adb_path else "[red]Not found[/red]",
        adb_path or "Install Android SDK Platform Tools",
    )

    try:
        import androguard

        table.add_row(
            "androguard",
            "[green]Installed[/green]",
            androguard.__version__ if hasattr(androguard, "__version__") else "OK",
        )
    except ImportError:
        table.add_row("androguard", "[yellow]Not installed[/yellow]", "pip install androguard")

    try:
        import yara

        table.add_row(
            "yara-python",
            "[green]Installed[/green]",
            yara.YARA_VERSION if hasattr(yara, "YARA_VERSION") else "OK",
        )
    except ImportError:
        table.add_row("yara-python", "[yellow]Not installed[/yellow]", "pip install yara-python")

    try:
        import aiohttp

        table.add_row("aiohttp", "[green]Installed[/green]", getattr(aiohttp, "__version__", "OK"))
    except ImportError:
        table.add_row("aiohttp", "[red]Not installed[/red]", "pip install aiohttp")

    try:
        import httpx

        table.add_row("httpx", "[green]Installed[/green]", getattr(httpx, "__version__", "OK"))
    except ImportError:
        table.add_row("httpx", "[red]Not installed[/red]", "pip install httpx")

    try:
        import rich

        table.add_row("Rich", "[green]Installed[/green]", getattr(rich, "__version__", "OK"))
    except ImportError:
        table.add_row("Rich", "[red]Not installed[/red]", "pip install rich")

    try:
        import textual

        table.add_row("Textual", "[green]Installed[/green]", getattr(textual, "__version__", "OK"))
    except ImportError:
        table.add_row("Textual", "[yellow]Not installed[/yellow]", "pip install textual")

    try:
        import yaml

        table.add_row("PyYAML", "[green]Installed[/green]", getattr(yaml, "__version__", "OK"))
    except ImportError:
        table.add_row("PyYAML", "[red]Not installed[/red]", "pip install pyyaml")

    try:
        import sqlite3

        table.add_row("SQLite3", "[green]Available[/green]", sqlite3.sqlite_version)
    except ImportError:
        table.add_row("SQLite3", "[red]Not available[/red]", "")

    table.add_row(
        "Python",
        "[green]OK[/green]",
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    )

    console.print(table)

    async def _check_device() -> None:
        from aegisdroid.adb.adapter import ADBAdapter

        adb = ADBAdapter(_get_config(config).adb)
        devices = await adb.list_devices()
        if devices:
            console.print("\n[green]Connected devices:[/green]")
            for d in devices:
                console.print(f"  {d.get('serial', 'unknown')} ({d.get('state', 'unknown')})")
        else:
            console.print("\n[yellow]No ADB devices connected.[/yellow]")

    _run_async(_check_device())


# ──────────────────────────────────────────────────
#  aegis config
# ──────────────────────────────────────────────────


@app.command()
def config_cmd(
    action: str = typer.Argument("show", help="Action: show, init"),
    config: str | None = CONFIG_OPTION,
) -> None:
    """Show or initialize configuration."""
    _print_banner()

    if action == "show":
        cfg = _get_config(config)
        import yaml
        from rich.syntax import Syntax

        data = {
            "adb": cfg.adb.__dict__,
            "ai": cfg.ai.__dict__,
            "yara": cfg.yara.__dict__,
            "scan": cfg.scan.__dict__,
            "theme": cfg.theme.__dict__,
        }
        yaml_str = yaml.dump(data, default_flow_style=False)
        console.print(Syntax(yaml_str, "yaml", theme="monokai"))

    elif action == "init":
        from aegisdroid.core.config import DEFAULT_CONFIG_DIR

        cfg = AegisConfig()
        path = str(DEFAULT_CONFIG_DIR / "config.yaml")
        cfg.save(path)
        console.print(f"[green]Config initialized:[/green] {path}")


# ──────────────────────────────────────────────────
#  Main entry point
# ──────────────────────────────────────────────────


def main() -> None:
    logging.basicConfig(
        level=logging.DEBUG if "--debug" in sys.argv else logging.WARNING,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    app()


if __name__ == "__main__":
    main()

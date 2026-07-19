"""AegisDroid Interactive Menu - just type `aegis`."""

from __future__ import annotations

import asyncio
import contextlib
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from aegisdroid import __version__

console = Console()

BANNER_LINES = [
    "     ___  ________  _______   ____  ________  ___     ",
    "    /   |/_  __/ / / /   | |  / _ \\/ __/ __ \\/ _ \\    ",
    "   / /| | / / / /_/ / /| | | / /_/ / /_/ /_/ /  __/   ",
    "  / ___ |/ / / __  / ___ | |/ _, _/ __/ _, _/ /       ",
    " /_/  |_/_/ /_/ /_/_/  |_|____/_/ /_/ /_/ |_|/        ",
]

KNOWN_PACKAGES = {
    "youtube": "com.google.android.youtube",
    "whatsapp": "com.whatsapp",
    "instagram": "com.instagram.android",
    "facebook": "com.facebook.katana",
    "telegram": "org.telegram.messenger",
    "chrome": "com.android.chrome",
    "gmail": "com.google.android.gm",
    "maps": "com.google.android.apps.maps",
    "twitter": "com.twitter.android",
    "tiktok": "com.zhiliaoapp.musically",
    "snapchat": "com.snapchat.android",
    "spotify": "com.spotify.music",
    "netflix": "com.netflix.mediaclient",
    "paypal": "com.paypal.android.p2pmobile",
    "bank": "com.bankofamerica.cashpromobile",
    "zoom": "us.zoom.videomeetings",
    "teams": "com.microsoft.teams",
    "signal": "org.thoughtcrime.securesms",
    "discord": "com.discord",
    "reddit": "com.reddit.frontpage",
    "twitch": "tv.twitch.android.app",
    "uber": "com.ubercab",
    "lyft": "me.lyft.android",
    "amazon": "com.amazon.mShop.android.shopping",
    "aliexpress": "com.alibaba.aliexpresshd",
    "flipkart": "com.flipkart.android",
    "chrome-beta": "com.chrome.beta",
    "firefox": "org.mozilla.firefox",
    "opera": "com.opera.browser",
    "brave": "com.brave.browser",
    "edge": "com.microsoft.emmx",
    "camera": "com.android.camera",
    "gallery": "com.android.gallery3d",
    "contacts": "com.android.contacts",
    "phone": "com.android.dialer",
    "messages": "com.android.mms",
    "clock": "com.android.deskclock",
    "calculator": "com.android.calculator2",
    "calendar": "com.android.calendar",
    "files": "com.android.filemanager",
    "settings": "com.android.settings",
    "play store": "com.android.vending",
    "playstore": "com.android.vending",
    "google play": "com.android.vending",
}

MENU_LEFT = [
    ("Quick Device Scan", "scan_quick"),
    ("Full Device Scan", "scan_full"),
    ("Deep Scan (YARA)", "scan_deep"),
    ("Scan Specific App", "scan_package"),
    ("Analyze APK File", "analyze_apk"),
    ("Threat Hunt", "hunt"),
    ("Root & Hook Detection", "detect_root"),
    ("Boot Security Check", "analyze_boot"),
    ("Filesystem Integrity", "check_filesystem"),
    ("Network Analysis", "analyze_network"),
]

MENU_RIGHT = [
    ("Forensic Timeline", "timeline"),
    ("YARA Scan", "yara_scan"),
    ("Live Device Monitor", "monitor"),
    ("Compare Scans (diff)", "diff_scans"),
    ("Search Past Scans", "search"),
    ("Generate Report", "report"),
    ("View Past Scans", "list_scans"),
    ("Install Requirements", "install_req"),
    ("System Diagnostics", "doctor"),
    ("Exit", "exit"),
]

ALL_OPTIONS = MENU_LEFT + MENU_RIGHT


def _center(text: str, width: int = 62) -> str:
    return text.center(width)


def print_banner() -> None:
    os.system("clear" if os.name != "nt" else "cls")

    banner_text = Text()
    for line in BANNER_LINES:
        banner_text.append(line + "\n", style="bold green")
    banner_text.append(
        _center(f"v{__version__} - Advanced Android Security Framework") + "\n",
        style="dim white",
    )
    banner_text.append(
        _center("Defensive Security & Digital Forensics Only"),
        style="dim yellow",
    )
    console.print(Panel(banner_text, border_style="green", expand=False, padding=(0, 0)))


def print_menu() -> None:
    console.print()

    left_table = Table(show_header=True, box=None, padding=(0, 1))
    left_table.add_column("#", style="bold green", width=4, justify="right")
    left_table.add_column("Option", style="white", min_width=22)

    right_table = Table(show_header=True, box=None, padding=(0, 1))
    right_table.add_column("#", style="bold green", width=4, justify="right")
    right_table.add_column("Option", style="white", min_width=22)

    for i, (label, key) in enumerate(MENU_LEFT, 1):
        left_table.add_row(str(i), label)

    for i, (label, key) in enumerate(MENU_RIGHT, 11):
        if key == "exit":
            right_table.add_row(f"[bold red]{i}[/bold red]", f"[red]{label}[/red]")
        else:
            right_table.add_row(str(i), label)

    columns = Columns([left_table, right_table], padding=(0, 4), expand=True)
    console.print(columns)
    console.print()


def get_choice() -> str:
    try:
        choice = console.input(f"  [bold green]Choose option (1-{len(ALL_OPTIONS)}): [/bold green]")
        return choice.strip()
    except (EOFError, KeyboardInterrupt):
        return str(len(ALL_OPTIONS))


def get_input(prompt: str) -> str:
    try:
        return console.input(f"  [cyan]{prompt}: [/cyan]").strip()
    except (EOFError, KeyboardInterrupt):
        return ""


def press_enter() -> None:
    with contextlib.suppress(EOFError, KeyboardInterrupt):
        console.input("\n  [dim]Press Enter to continue...[/dim]")


def _run_async(coro):  # type: ignore
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures

            with concurrent.futures.ThreadPoolExecutor() as pool:
                return pool.submit(asyncio.run, coro).result()
        else:
            if loop.is_closed():
                raise RuntimeError("closed")
            return loop.run_until_complete(coro)
    except (RuntimeError, AttributeError):
        return asyncio.run(coro)


def _connect_adb(config: Any = None) -> Any:  # type: ignore
    """Helper to get a connected ADB adapter, or None."""
    from aegisdroid.adb.adapter import ADBAdapter
    from aegisdroid.core.config import load_config

    cfg = config or load_config()
    return ADBAdapter(cfg.adb)


def _resolve_package(name: str) -> str:
    """Resolve an app name to its package name."""
    lower = name.lower().strip()
    if lower in KNOWN_PACKAGES:
        return KNOWN_PACKAGES[lower]
    if "." in lower and len(lower.split(".")) >= 3:
        return lower
    return lower


# ──────────────────────────────────────────────────────────
#  Action implementations
# ──────────────────────────────────────────────────────────


def action_scan_quick() -> None:
    from aegisdroid.core.config import load_config
    from aegisdroid.database.store import Database
    from aegisdroid.scanner.engine import Scanner

    async def _run() -> None:
        scanner = Scanner(load_config())
        with console.status("[bold green]Connecting to device and scanning...", spinner="dots"):
            result = await scanner.quick_scan()

        db = Database()
        await db.initialize()
        try:
            await db.save_scan(result)
        finally:
            await db.close()

        _display_scan_result(result)

    _run_async(_run())
    press_enter()


def action_scan_full() -> None:
    from aegisdroid.core.config import load_config
    from aegisdroid.database.store import Database
    from aegisdroid.reports.generator import ReportGenerator
    from aegisdroid.scanner.engine import Scanner

    async def _run() -> None:
        scanner = Scanner(load_config())
        with console.status(
            "[bold green]Running full device scan (this may take a while)...", spinner="dots"
        ):
            result = await scanner.full_scan()

        db = Database()
        await db.initialize()
        try:
            await db.save_scan(result)
        finally:
            await db.close()

        _display_scan_result(result)

        console.print("\n[bold green]Saving detailed HTML report...[/bold green]")
        gen = ReportGenerator()
        path = await gen.generate(result, format="html")
        console.print(f"[green]Full report saved to:[/green] {path}")

    _run_async(_run())
    press_enter()


def action_scan_deep() -> None:
    from aegisdroid.core.config import load_config
    from aegisdroid.database.store import Database
    from aegisdroid.reports.generator import ReportGenerator
    from aegisdroid.scanner.engine import Scanner

    async def _run() -> None:
        scanner = Scanner(load_config())
        with console.status("[bold green]Running deep scan with YARA...", spinner="dots"):
            result = await scanner.deep_scan()

        db = Database()
        await db.initialize()
        try:
            await db.save_scan(result)
        finally:
            await db.close()

        _display_scan_result(result)

        console.print("\n[bold green]Saving detailed HTML report...[/bold green]")
        gen = ReportGenerator()
        path = await gen.generate(result, format="html")
        console.print(f"[green]Full report saved to:[/green] {path}")

    _run_async(_run())
    press_enter()


def action_scan_package() -> None:
    name = get_input("Enter app name or package name (e.g., youtube, com.whatsapp)")
    if not name:
        console.print("[red]No name entered.[/red]")
        press_enter()
        return

    package = _resolve_package(name)
    console.print(f"  [dim]Resolved to: {package}[/dim]")

    from aegisdroid.core.config import load_config
    from aegisdroid.database.store import Database
    from aegisdroid.scanner.engine import Scanner

    async def _run() -> None:
        scanner = Scanner(load_config())
        with console.status(f"[bold green]Scanning {package}...", spinner="dots"):
            result = await scanner.target_scan(package)

        db = Database()
        await db.initialize()
        try:
            await db.save_scan(result)
        finally:
            await db.close()

        _display_scan_result(result)

    _run_async(_run())
    press_enter()


def action_analyze_apk() -> None:
    path = get_input("Enter path to APK file")
    if not path or not Path(path).exists():
        console.print("[red]File not found.[/red]")
        press_enter()
        return

    from aegisdroid.apk.analyzer import APKAnalyzer

    async def _run() -> None:
        analyzer = APKAnalyzer()
        with console.status("[bold green]Analyzing APK...", spinner="dots"):
            app_info = await analyzer.analyze(path)
        _display_apk_result(app_info)

    _run_async(_run())
    press_enter()


def action_hunt() -> None:
    console.print("[bold]Threat Hunting - search the device for specific patterns[/bold]\n")
    console.print("  [dim]Examples:[/dim]")
    console.print("  [dim]  camera internet          (finds apps using camera + internet)[/dim]")
    console.print("  [dim]  accessibility overlay     (finds accessibility + overlay abuse)[/dim]")
    console.print("  [dim]  native dynamic           (finds apps with native + dynamic code)[/dim]")
    console.print("  [dim]  root frida               (finds root + frida indicators)[/dim]")
    console.print("  [dim]  debug certificate        (finds debug-signed apps)[/dim]")
    console.print()
    query = get_input("Enter hunt terms")
    if not query:
        console.print("[red]No query entered.[/red]")
        press_enter()
        return

    from aegisdroid.core.config import load_config
    from aegisdroid.database.store import Database
    from aegisdroid.scanner.engine import Scanner

    async def _run() -> None:
        scanner = Scanner(load_config())
        adb = scanner.adb
        with console.status("[bold green]Connecting to device and analyzing...", spinner="dots"):
            connected = await adb.connect()
            if not connected:
                console.print("[red]No device connected.[/red]")
                return
            result = await scanner.full_scan()

        db = Database()
        await db.initialize()
        try:
            await db.save_scan(result)

            query_lower = query.lower()
            terms = [t.strip() for t in query_lower.split() if t.strip()]

            matched = []
            for f in result.findings:
                searchable = f"{f.title} {f.description} {f.category.value} {f.mitigation}".lower()
                if all(term in searchable for term in terms):
                    matched.append(f)

            if matched:
                console.print(f"\n[bold green]Hunt matched {len(matched)} findings:[/bold green]\n")
                for f in matched:
                    sev_color = _severity_color(f.severity)
                    console.print(
                        f"  [{sev_color}]{f.severity.value.upper()}[/{sev_color}] {f.title}"
                    )
                    console.print(f"    {f.description[:100]}")
                    for e in f.evidence[:2]:
                        console.print(f"    [dim]• {e.description}[/dim]")
                    if f.mitigation:
                        console.print(f"    [yellow]Mitigation:[/yellow] {f.mitigation}")
                    console.print()
            else:
                console.print("[yellow]No findings matched your hunt query.[/yellow]")
                console.print(
                    "[dim]Tip: try broader terms. Current findings cover: "
                    + ", ".join(sorted({f.category.value for f in result.findings}))[:100]
                    + "[/dim]"
                )
        finally:
            await db.close()

    _run_async(_run())
    press_enter()


def action_detect_root() -> None:
    from aegisdroid.threats.root_detector import RootDetector

    async def _run() -> None:
        adb = _connect_adb()
        with console.status(
            "[bold green]Checking for root and hooking frameworks...", spinner="dots"
        ):
            connected = await adb.connect()
            if not connected:
                console.print("[red]No device connected.[/red]")
                return
            device_info = await adb.get_device_info()
            detector = RootDetector(adb)
            findings = await detector.detect(device_info)

        if findings:
            console.print(
                f"\n[bold red]Found {len(findings)} root/hooking indicators:[/bold red]\n"
            )
            for f in findings:
                sev_color = _severity_color(f.severity)
                console.print(f"  [{sev_color}]{f.severity.value.upper()}[/{sev_color}] {f.title}")
                console.print(f"    {f.description}")
                for e in f.evidence[:3]:
                    console.print(f"    [dim]• {e.description}[/dim]")
                if f.mitigation:
                    console.print(f"    [yellow]Mitigation:[/yellow] {f.mitigation}")
                if f.references:
                    for ref in f.references:
                        console.print(f"    [blue]Ref: {ref}[/blue]")
                console.print()
        else:
            console.print("[green]No root or hooking frameworks detected.[/green]")

    _run_async(_run())
    press_enter()


def action_analyze_boot() -> None:
    from aegisdroid.threats.boot_analyzer import BootAnalyzer

    async def _run() -> None:
        adb = _connect_adb()
        with console.status("[bold green]Analyzing boot chain...", spinner="dots"):
            connected = await adb.connect()
            if not connected:
                console.print("[red]No device connected.[/red]")
                return
            analyzer = BootAnalyzer(adb)
            findings = await analyzer.detect_boot_findings()
            boot_data = await analyzer.analyze_boot()

        if findings:
            console.print("\n[bold yellow]Boot security findings:[/bold yellow]\n")
            for f in findings:
                sev_color = _severity_color(f.severity)
                console.print(f"  [{sev_color}]{f.severity.value.upper()}[/{sev_color}] {f.title}")
                console.print(f"    {f.description}")
                for e in f.evidence[:3]:
                    console.print(f"    [dim]• {e.description}[/dim]")
                if f.mitigation:
                    console.print(f"    [yellow]Mitigation:[/yellow] {f.mitigation}")
                console.print()

        console.print("[bold]Boot Chain Details:[/bold]\n")
        for key, val in boot_data.items():
            if isinstance(val, dict):
                console.print(f"  [bold]{key}:[/bold]")
                for k, v in val.items():
                    console.print(f"    {k}: {v}")
            else:
                console.print(f"  [bold]{key}:[/bold] {val}")

    _run_async(_run())
    press_enter()


def action_check_filesystem() -> None:
    from aegisdroid.forensics.filesystem import FilesystemForensics

    EXPLANATIONS = {
        "Root indicator file found": (
            "This file is a well-known indicator of a rooted device. "
            "Root solutions place binaries like 'su' or 'busybox' in these "
            "locations to provide elevated privileges. Their presence means "
            "the device has been rooted or a root toolkit is installed."
        ),
        "Executable files in writable location": (
            "Executable files in /data/local/tmp or /sdcard are unusual. "
            "System apps store binaries in /system or /vendor (read-only). "
            "Executables in writable locations may indicate a root tool, "
            "malware dropper, or manually placed binary for exploitation."
        ),
        "Script files found in system partition": (
            "Script files (.sh, .pl, .py) in the system partition are unusual "
            "on production devices. These may be leftover from custom ROMs, "
            "root scripts that modify system behavior, or add-on scripts "
            "(like addon.d survival scripts used by custom recoveries)."
        ),
        "SUID files found": (
            "SUID (Set User ID) binaries run with the file owner's privileges "
            "(usually root). While some SUID files are normal (like 'su' on "
            "rooted devices), non-standard SUID binaries can be used for "
            "privilege escalation or maintaining root access."
        ),
        "Modified system files detected": (
            "System files have been modified since the last baseline was set. "
            "This can indicate: firmware tampering, root modifications, "
            "custom ROM installation, or potential malware altering system "
            "binaries to maintain persistence or hide its presence."
        ),
    }

    async def _run() -> None:
        adb = _connect_adb()
        with console.status("[bold green]Checking filesystem integrity...", spinner="dots"):
            connected = await adb.connect()
            if not connected:
                console.print("[red]No device connected.[/red]")
                return
            fs = FilesystemForensics(adb)
            findings = await fs.find_suspicious_files()
            suid_findings = await fs.find_suid_files()
            findings.extend(suid_findings)

        if findings:
            console.print("\n[bold yellow]Filesystem Integrity Report[/bold yellow]\n")
            for f in findings:
                sev_color = _severity_color(f.severity)
                console.print(f"  [{sev_color}]{f.severity.value.upper()}[/{sev_color}] {f.title}")

                explanation = ""
                for key, desc in EXPLANATIONS.items():
                    if key.lower() in f.title.lower():
                        explanation = desc
                        break

                if explanation:
                    console.print(f"    [bold]What this means:[/bold] {explanation}")

                console.print(f"    [bold]Description:[/bold] {f.description}")
                for e in f.evidence[:5]:
                    console.print(f"    [dim]• {e.description}[/dim]")
                if f.mitigation:
                    console.print(f"    [yellow]Mitigation:[/yellow] {f.mitigation}")
                console.print()
        else:
            console.print("[green]No suspicious filesystem artifacts found.[/green]")

    _run_async(_run())
    press_enter()


def action_analyze_network() -> None:
    from aegisdroid.forensics.network import NetworkAnalyzer

    async def _run() -> None:
        adb = _connect_adb()
        with console.status("[bold green]Analyzing network connections...", spinner="dots"):
            connected = await adb.connect()
            if not connected:
                console.print("[red]No device connected.[/red]")
                return
            net = NetworkAnalyzer(adb)
            connections = await net.analyze_connections()
            findings = await net.detect_network_findings()
            vpn = await net.analyze_vpn()
            dns = await net.analyze_dns()

        table = Table(title="Active Network Connections", box=box.ROUNDED)
        table.add_column("Remote IP", min_width=16)
        table.add_column("Port", width=8)
        table.add_column("Protocol", width=8)
        table.add_column("Encrypted", width=10)
        table.add_column("Suspicious", width=10)

        for c in connections[:30]:
            enc = "[green]Yes[/green]" if c.is_encrypted else "[yellow]No[/yellow]"
            susp = "[red]Yes[/red]" if c.suspicious else "No"
            table.add_row(c.ip, str(c.port), c.protocol, enc, susp)

        if connections:
            console.print(table)
        else:
            console.print("[yellow]No active TCP connections found.[/yellow]")

        if vpn.get("tun0_active"):
            console.print("\n[bold yellow]VPN is active (tun0 interface detected)[/bold yellow]")
        if vpn.get("http_proxy") and vpn["http_proxy"] != "none":
            console.print(f"[yellow]HTTP Proxy configured: {vpn['http_proxy']}[/yellow]")

        if dns:
            console.print("\n[bold]DNS Configuration:[/bold]")
            for d in dns:
                if d.get("type") == "nameserver":
                    console.print(f"  Nameserver: {d['address']}")
                elif d.get("type") == "private_dns":
                    console.print(f"  Private DNS: {d['specifier']}")

        if findings:
            console.print("\n[bold]Network Security Findings:[/bold]")
            for f in findings:
                sev_color = _severity_color(f.severity)
                console.print(f"  [{sev_color}]{f.severity.value.upper()}[/{sev_color}] {f.title}")
                console.print(f"    {f.description}")
                for e in f.evidence[:3]:
                    console.print(f"    [dim]• {e.description}[/dim]")
                console.print()

    _run_async(_run())
    press_enter()


def action_timeline() -> None:
    from aegisdroid.timeline.engine import TimelineEngine

    async def _run() -> None:
        adb = _connect_adb()
        with console.status("[bold green]Generating forensic timeline...", spinner="dots"):
            connected = await adb.connect()
            if not connected:
                console.print("[red]No device connected.[/red]")
                return
            engine = TimelineEngine(adb)
            events = await engine.generate_timeline()

        if events:
            table = Table(title="Forensic Timeline", box=box.ROUNDED)
            table.add_column("Timestamp", width=20)
            table.add_column("Category", width=18)
            table.add_column("Event", min_width=40)
            table.add_column("Severity", width=10)

            for e in events[:50]:
                sev_color = _severity_color(e.severity)
                table.add_row(
                    e.timestamp.strftime("%Y-%m-%d %H:%M:%S") if e.timestamp else "?",
                    e.category,
                    e.title,
                    f"[{sev_color}]{e.severity.value}[/{sev_color}]",
                )
            console.print(table)
        else:
            console.print("[yellow]No timeline events found.[/yellow]")

    _run_async(_run())
    press_enter()


def action_yara_scan() -> None:
    path = get_input("Enter file or directory path to scan")
    if not path:
        console.print("[red]No path entered.[/red]")
        press_enter()
        return

    from aegisdroid.yara.engine import YaraEngine

    async def _run() -> None:
        engine = YaraEngine()
        target = Path(path)
        with console.status("[bold green]Running YARA scan...", spinner="dots"):
            if target.is_file():
                if str(path).endswith(".apk"):
                    matches = await engine.scan_apk(path)
                else:
                    matches = await engine.scan_file(path)
            elif target.is_dir():
                matches = await engine.scan_directory(path)
            else:
                console.print("[red]Path not found.[/red]")
                return

        if matches:
            table = Table(title="YARA Matches", box=box.ROUNDED)
            table.add_column("Rule", style="bold")
            table.add_column("File")
            table.add_column("Description")
            for m in matches:
                table.add_row(m.rule_name, m.file_path, m.description[:60] if m.description else "")
            console.print(table)
        else:
            console.print("[green]No YARA matches found.[/green]")

    _run_async(_run())
    press_enter()


def action_monitor() -> None:
    interval = get_input("Poll interval in seconds (default: 5)")
    try:
        interval = float(interval) if interval else 5.0
    except ValueError:
        interval = 5.0

    from aegisdroid.adb.adapter import ADBAdapter
    from aegisdroid.core.config import load_config
    from aegisdroid.live.monitor import LiveMonitor

    async def _run() -> None:
        cfg = load_config()
        cfg.live_monitor.poll_interval = interval
        adb = ADBAdapter(cfg.adb)
        connected = await adb.connect()
        if not connected:
            console.print("[red]No device connected.[/red]")
            return

        console.print(f"[bold green]Live monitor started (polling every {interval}s)[/bold green]")
        console.print(
            "[dim]Watching for: new apps, permission changes, USB debugging, accessibility, VPN, certificates...[/dim]"
        )
        console.print("[dim]Press Ctrl+C to stop[/dim]\n")

        device_info = await adb.get_device_info()
        console.print(
            f"  [dim]Device: {device_info.manufacturer} {device_info.model} ({device_info.serial})[/dim]"
        )
        console.print(
            f"  [dim]Android: {device_info.android_version} (SDK {device_info.sdk_level})[/dim]\n"
        )

        monitor = LiveMonitor(adb, cfg.live_monitor)

        from aegisdroid.core.events import Event, event_bus

        alert_count = 0

        async def on_alert(event: Event) -> None:
            nonlocal alert_count
            if event.name == "live.monitor.tick":
                return
            alert_count += 1
            ts = datetime.now().strftime("%H:%M:%S")
            data = event.data
            sev = data.get("severity", "info")
            sev_color = {"high": "bold red", "medium": "yellow", "low": "blue"}.get(sev, "white")
            console.print(f"  [{sev_color}][{ts}] ALERT #{alert_count}:[/{sev_color}] {event.name}")
            if "package" in data:
                console.print(f"    Package: {data['package']}")
            if "service" in data:
                console.print(f"    Service: {data['service']}")
            if "old" in data and "new" in data:
                console.print(f"    Changed: {data['old']} -> {data['new']}")

        event_bus.subscribe("*", on_alert)

        tick_count = 0
        try:
            while True:
                await asyncio.sleep(interval)
                tick_count += 1
                if tick_count % 6 == 0:
                    ts = datetime.now().strftime("%H:%M:%S")
                    console.print(f"  [dim][{ts}] Monitoring... ({alert_count} alerts)[/dim]")
        except KeyboardInterrupt:
            await monitor.stop()
            console.print(f"\n[yellow]Monitor stopped. Total alerts: {alert_count}[/yellow]")

    _run_async(_run())
    press_enter()


def action_diff_scans() -> None:
    from aegisdroid.database.store import Database
    from aegisdroid.diff.engine import DiffEngine

    async def _run() -> None:
        db = Database()
        await db.initialize()
        try:
            scans = await db.list_scans(10)

            if len(scans) < 2:
                console.print(
                    "[yellow]Need at least 2 scans to compare. Run some scans first.[/yellow]"
                )
                return

            table = Table(title="Available Scans", box=box.SIMPLE)
            table.add_column("#", width=4, justify="right")
            table.add_column("ID", width=10)
            table.add_column("Type", width=10)
            table.add_column("Package", width=25)
            table.add_column("Date", width=18)
            table.add_column("Score", width=8)

            for i, s in enumerate(scans[:10], 1):
                table.add_row(
                    str(i),
                    s.id[:8],
                    s.scan_type.value,
                    s.package_name or "(device)",
                    s.started_at.strftime("%Y-%m-%d %H:%M"),
                    f"{s.threat_confidence_score:.0%}",
                )
            console.print(table)

            first = get_input("Enter first scan number")
            second = get_input("Enter second scan number")
            try:
                idx1 = int(first) - 1
                idx2 = int(second) - 1
                if 0 <= idx1 < len(scans) and 0 <= idx2 < len(scans):
                    engine = DiffEngine()
                    result = engine.diff(scans[idx1], scans[idx2])
                    output = engine.format_diff(result)
                    console.print(output)
                else:
                    console.print("[red]Invalid scan numbers.[/red]")
            except (ValueError, IndexError):
                console.print(f"[red]Invalid input. Enter numbers 1-{len(scans)}.[/red]")
        finally:
            await db.close()

    _run_async(_run())
    press_enter()


def action_search() -> None:
    query = get_input("Enter search query")
    if not query:
        return

    from aegisdroid.database.store import Database
    from aegisdroid.search.engine import SearchEngine

    async def _run() -> None:
        db = Database()
        await db.initialize()
        try:
            engine = SearchEngine()
            scans = await db.list_scans(100)
            if not scans:
                console.print("[yellow]No scans found. Run a scan first.[/yellow]")
                return
            for scan in scans:
                engine.index_scan(scan)

            results = engine.search(query)
            if results:
                table = Table(title=f"Search: {query}", box=box.ROUNDED)
                table.add_column("Type", width=10)
                table.add_column("Score", width=8)
                table.add_column("Details", min_width=40)
                for r in results[:20]:
                    if r["type"] == "finding":
                        f = r["data"]
                        sev_color = _severity_color(f.severity)
                        table.add_row(
                            "Finding",
                            f"{r['score']:.2f}",
                            f"[{sev_color}]{f.severity.value.upper()}[/{sev_color}] {f.title}",
                        )
                    else:
                        table.add_row(r["type"], f"{r['score']:.2f}", str(r["data"])[:80])
                console.print(table)
            else:
                console.print("[yellow]No results found.[/yellow]")
        finally:
            await db.close()

    _run_async(_run())
    press_enter()


def action_report() -> None:
    from aegisdroid.database.store import Database
    from aegisdroid.reports.generator import ReportGenerator

    async def _run() -> None:
        db = Database()
        await db.initialize()
        try:
            scans = await db.list_scans(10)

            if not scans:
                console.print("[yellow]No scans found. Run a scan first.[/yellow]")
                return

            table = Table(title="Select Scan for Report", box=box.SIMPLE)
            table.add_column("#", width=4, justify="right")
            table.add_column("Type", width=10)
            table.add_column("Package", width=25)
            table.add_column("Date", width=18)
            table.add_column("Score", width=8)
            table.add_column("Findings", width=8)

            for i, s in enumerate(scans[:10], 1):
                table.add_row(
                    str(i),
                    s.scan_type.value,
                    s.package_name or "(device)",
                    s.started_at.strftime("%Y-%m-%d %H:%M"),
                    f"{s.threat_confidence_score:.0%}",
                    str(len(s.findings)),
                )
            console.print(table)

            choice = get_input("Enter scan number (or press Enter for latest)")
            try:
                idx = int(choice) - 1 if choice else 0
                if not (0 <= idx < len(scans)):
                    idx = 0
            except ValueError:
                idx = 0

            fmt = get_input("Format (markdown / html / json / sarif) [default: html]") or "html"
            gen = ReportGenerator()
            with console.status("[bold green]Generating report...", spinner="dots"):
                path = await gen.generate(scans[idx], format=fmt)
            console.print(f"\n[green]Report saved to:[/green] {path}")
        finally:
            await db.close()

    _run_async(_run())
    press_enter()


def action_list_scans() -> None:
    from aegisdroid.database.store import Database

    async def _run() -> None:
        db = Database()
        await db.initialize()
        try:
            scans = await db.list_scans(20)

            if not scans:
                console.print("[yellow]No scans found. Run a scan first.[/yellow]")
                return

            table = Table(title="Past Scans", box=box.ROUNDED)
            table.add_column("ID", width=10)
            table.add_column("Type", width=10)
            table.add_column("Package", width=25)
            table.add_column("Date", width=18)
            table.add_column("Duration", width=10)
            table.add_column("Score", width=8)
            table.add_column("Findings", width=8)

            for s in scans:
                score_color = (
                    "red"
                    if s.threat_confidence_score >= 0.6
                    else "yellow"
                    if s.threat_confidence_score >= 0.3
                    else "green"
                )
                table.add_row(
                    s.id[:8],
                    s.scan_type.value,
                    s.package_name or "(device)",
                    s.started_at.strftime("%Y-%m-%d %H:%M"),
                    f"{s.duration:.1f}s",
                    f"[{score_color}]{s.threat_confidence_score:.0%}[/{score_color}]",
                    str(len(s.findings)),
                )
            console.print(table)
        finally:
            await db.close()

    _run_async(_run())
    press_enter()


def action_install_req() -> None:
    console.print("\n[bold]Installing AegisDroid Requirements[/bold]\n")

    project_root = Path(__file__).parent.parent.parent
    venv_dir = project_root / ".venv"
    project_root / "requirements.txt"

    if not venv_dir.exists():
        console.print("[cyan]Creating virtual environment...[/cyan]")
        subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
        console.print("[green]Virtual environment created at .venv/[/green]")
    else:
        console.print("[green]Virtual environment already exists at .venv/[/green]")

    venv_python = venv_dir / "bin" / "python"
    if not venv_python.exists():
        venv_python = venv_dir / "Scripts" / "python.exe"

    core_deps = [
        "typer>=0.12.0",
        "rich>=13.7.0",
        "pydantic>=2.6.0",
        "pyyaml>=6.0.1",
        "aiohttp>=3.9.0",
        "aiosqlite>=0.19.0",
        "httpx>=0.27.0",
        "cryptography>=42.0.0",
        "lxml>=5.1.0",
        "python-magic>=0.4.27",
        "jinja2>=3.1.3",
        "markdown>=3.5.0",
        "tabulate>=0.9.0",
        "psutil>=5.9.0",
        "tqdm>=4.66.0",
        "gitpython>=3.1.41",
        "semver>=3.0.2",
        "packaging>=24.0",
    ]

    console.print("[cyan]Installing core dependencies...[/cyan]")
    result = subprocess.run(
        [str(venv_python), "-m", "pip", "install", *core_deps],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        console.print("[green]Core dependencies installed successfully.[/green]")
    else:
        console.print(f"[red]Some dependencies failed:[/red]\n{result.stderr[-300:]}")

    console.print(
        "\n[cyan]Installing optional: androguard + yara-python (for APK analysis)...[/cyan]"
    )
    subprocess.run(
        [str(venv_python), "-m", "pip", "install", "androguard>=4.0", "yara-python>=4.3.0"],
        capture_output=True,
        text=True,
    )

    console.print("\n[cyan]Installing dev tools: pytest, ruff, mypy...[/cyan]")
    subprocess.run(
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "pytest>=8.0.0",
            "pytest-asyncio>=0.23.0",
            "ruff>=0.2.0",
            "mypy>=1.8.0",
        ],
        capture_output=True,
        text=True,
    )

    console.print("\n[cyan]Installing AegisDroid package in editable mode...[/cyan]")
    result = subprocess.run(
        [str(venv_python), "-m", "pip", "install", "-e", ".", "--no-deps"],
        cwd=str(project_root),
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        console.print("[green]AegisDroid installed successfully![/green]")
    else:
        console.print(f"[red]Package install failed:[/red]\n{result.stderr[-300:]}")

    console.print("\n[bold green]Done![/bold green]")
    console.print(f"[dim]Activate with: source {venv_dir}/bin/activate[/dim]")
    console.print("[dim]Then run: aegis[/dim]")


def action_doctor() -> None:
    import shutil

    console.print("\n[bold]System Diagnostics[/bold]\n")

    table = Table(box=box.ROUNDED)
    table.add_column("Component", style="bold")
    table.add_column("Status")
    table.add_column("Details")

    adb_path = shutil.which("adb")
    table.add_row(
        "ADB",
        "[green]Found[/green]" if adb_path else "[red]Not found[/red]",
        adb_path or "Install Android SDK Platform Tools",
    )

    try:
        import androguard

        table.add_row(
            "androguard", "[green]Installed[/green]", getattr(androguard, "__version__", "OK")
        )
    except ImportError:
        table.add_row("androguard", "[yellow]Optional[/yellow]", "pip install androguard")

    try:
        import yara

        table.add_row(
            "yara-python", "[green]Installed[/green]", getattr(yara, "YARA_VERSION", "OK")
        )
    except ImportError:
        table.add_row("yara-python", "[yellow]Optional[/yellow]", "pip install yara-python")

    try:
        import rich as r

        table.add_row("Rich", "[green]OK[/green]", getattr(r, "__version__", "OK"))
    except ImportError:
        table.add_row("Rich", "[red]Required[/red]", "pip install rich")

    try:
        import pydantic

        table.add_row("Pydantic", "[green]OK[/green]", getattr(pydantic, "__version__", "OK"))
    except ImportError:
        table.add_row("Pydantic", "[red]Required[/red]", "pip install pydantic")

    try:
        import yaml

        table.add_row("PyYAML", "[green]OK[/green]", getattr(yaml, "__version__", "OK"))
    except ImportError:
        table.add_row("PyYAML", "[red]Required[/red]", "pip install pyyaml")

    table.add_row(
        "Python",
        "[green]OK[/green]",
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    )
    table.add_row("Platform", "[green]OK[/green]", sys.platform)

    console.print(table)

    async def _check_device() -> None:
        from aegisdroid.adb.adapter import ADBAdapter
        from aegisdroid.core.config import load_config

        adb = ADBAdapter(load_config().adb)
        devices = await adb.list_devices()
        if devices:
            console.print("\n[green]Connected devices:[/green]")
            for d in devices:
                serial = d.get("serial", "?")
                state = d.get("state", "?")
                model = d.get("model", "")
                console.print(f"  {serial} ({state}) {model}")
        else:
            console.print("\n[yellow]No ADB devices connected.[/yellow]")
            console.print("[dim]Connect a device with USB debugging enabled.[/dim]")

    _run_async(_check_device())


def action_settings() -> None:
    from aegisdroid.core.config import DEFAULT_CONFIG_DIR, load_config

    cfg = load_config()

    table = Table(title="Current Settings", box=box.ROUNDED)
    table.add_column("Setting", style="bold")
    table.add_column("Value")

    table.add_row("ADB Path", cfg.adb.adb_path)
    table.add_row("ADB Timeout", f"{cfg.adb.timeout}s")
    table.add_row("AI Provider", cfg.ai.provider)
    table.add_row("AI Model", cfg.ai.model)
    table.add_row("AI Enabled", "Yes" if cfg.ai.enabled else "No")
    table.add_row("Default Scan Type", cfg.scan.default_type)
    table.add_row("Parallel Scans", "Yes" if cfg.scan.parallel else "No")
    table.add_row("Live Monitor Interval", f"{cfg.live_monitor.poll_interval}s")
    table.add_row("Theme", cfg.theme.name)

    console.print(table)
    console.print(f"\n[dim]Config file: {DEFAULT_CONFIG_DIR / 'config.yaml'}[/dim]")
    press_enter()


def action_exit() -> None:
    console.print("\n[bold green]Goodbye. Stay secure.[/bold green]\n")
    sys.exit(0)


# ──────────────────────────────────────────────────────────
#  Display helpers
# ──────────────────────────────────────────────────────────


def _severity_color(severity) -> str:  # type: ignore
    from aegisdroid.core.domain import Severity

    return {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "bold yellow",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
        Severity.NONE: "dim",
    }.get(severity, "white")


def _display_scan_result(result) -> None:  # type: ignore
    from aegisdroid.core.domain import Severity

    console.print()

    score = result.threat_confidence_score
    score_color = "bold red" if score >= 0.7 else "bold yellow" if score >= 0.4 else "green"
    risk_label = (
        "CRITICAL - Immediate action required"
        if score >= 0.7
        else "HIGH - Prompt investigation recommended"
        if score >= 0.5
        else "MODERATE - Review recommended"
        if score >= 0.3
        else "LOW - Minor observations"
        if score >= 0.1
        else "MINIMAL - No significant concerns"
    )
    console.print(
        Panel(
            f"[{score_color}]Threat Confidence Score: {score:.0%}[/{score_color}]\n"
            f"Risk Level: {risk_label}\n\n"
            f"Findings: {len(result.findings)} total | "
            f"[bold red]Critical: {result.total_critical}[/bold red] | "
            f"[bold yellow]High: {result.total_high}[/bold yellow] | "
            f"Medium: {sum(1 for f in result.findings if f.severity == Severity.MEDIUM)} | "
            f"Low: {sum(1 for f in result.findings if f.severity == Severity.LOW)} | "
            f"Info: {sum(1 for f in result.findings if f.severity == Severity.INFO)}",
            title="[bold]Scan Summary[/bold]",
            border_style="green" if score < 0.3 else "yellow" if score < 0.6 else "red",
        )
    )

    if result.error:
        console.print(f"\n[red]Scan error: {result.error}[/red]")

    if result.metadata.get("device"):
        d = result.metadata["device"]
        console.print(
            Panel(
                f"Model: {d.get('manufacturer', '?')} {d.get('model', '?')}\n"
                f"Android: {d.get('android_version', '?')} (SDK {d.get('sdk_level', '?')})\n"
                f"Build: {d.get('build_fingerprint', '?')[:60]}\n"
                f"Security Patch: {d.get('security_patch', '?')}\n"
                f"Rooted: {'Yes' if d.get('is_rooted') else 'Unknown'}",
                title="[bold]Device Info[/bold]",
                border_style="blue",
            )
        )

    profile = result.metadata.get("device_profile")
    if profile:
        _display_device_profile(profile)

    if result.findings:
        table = Table(title="Findings", box=box.ROUNDED, show_lines=True)
        table.add_column("Sev", style="bold", width=8)
        table.add_column("Category", width=20)
        table.add_column("Title", min_width=30)
        table.add_column("Conf", width=6)

        sorted_f = sorted(
            result.findings,
            key=lambda f: {
                Severity.CRITICAL: 0,
                Severity.HIGH: 1,
                Severity.MEDIUM: 2,
                Severity.LOW: 3,
                Severity.INFO: 4,
            }.get(f.severity, 5),
        )

        for f in sorted_f:
            sev_c = _severity_color(f.severity)
            table.add_row(
                f"[{sev_c}]{f.severity.value.upper()}[/{sev_c}]",
                f.category.value.replace("_", " ").title(),
                f.title,
                f"{f.confidence:.0%}",
            )
        console.print(table)

        console.print("\n[bold]Detailed Findings:[/bold]")
        for i, f in enumerate(sorted_f[:10], 1):
            sev_c = _severity_color(f.severity)
            console.print(
                f"\n  {i}. [{sev_c}]{f.severity.value.upper()}[/{sev_c}] [bold]{f.title}[/bold]"
            )
            console.print(f"     {f.description}")
            if f.evidence:
                console.print(f"     [dim]Evidence ({len(f.evidence)} items):[/dim]")
                for e in f.evidence[:3]:
                    console.print(f"       • {e.description}")
            if f.mitigation:
                console.print(f"     [yellow]Mitigation:[/yellow] {f.mitigation}")

        if len(sorted_f) > 10:
            console.print(
                f"\n  [dim]... and {len(sorted_f) - 10} more findings. Generate a report for full details.[/dim]"
            )
    else:
        console.print("\n[green]No findings detected. Device appears clean.[/green]")


def _display_device_profile(profile: dict) -> None:  # type: ignore
    hw = profile.get("hardware", {})
    os_info = profile.get("os", {})
    sec = profile.get("security", {})
    crypto = profile.get("crypto", {})
    kernel = profile.get("kernel", {})
    net = profile.get("network", {})
    pkg = profile.get("packages", {})
    proc = profile.get("processes", {})
    selinux = profile.get("selinux", {})

    t = Table(title="Complete Device Profile", box=box.ROUNDED, show_header=False)
    t.add_column("Key", style="bold cyan", width=28)
    t.add_column("Value", min_width=50)

    t.add_row("── Hardware ──", "")
    for k, v in hw.items():
        if v and v != "error":
            t.add_row(f"  {k}", str(v)[:120])

    t.add_row("── OS ──", "")
    for k, v in os_info.items():
        if v and v != "error":
            t.add_row(f"  {k}", str(v)[:120])

    t.add_row("── Kernel ──", "")
    for k, v in kernel.items():
        if v and v != "error":
            t.add_row(f"  {k}", str(v)[:120])

    t.add_row("── Security ──", "")
    for k, v in sec.items():
        if v and v != "error":
            t.add_row(f"  {k}", str(v)[:120])

    t.add_row("── SELinux ──", "")
    for k, v in selinux.items():
        if v and v != "error":
            t.add_row(f"  {k}", str(v)[:120])

    t.add_row("── Crypto/Encryption ──", "")
    for k, v in crypto.items():
        if v and v != "error":
            t.add_row(f"  {k}", str(v)[:120])

    t.add_row("── Network ──", "")
    for k, v in net.items():
        if v and v != "error":
            t.add_row(f"  {k}", str(v)[:120])

    t.add_row("── Packages ──", "")
    if pkg.get("third_party_count"):
        t.add_row("  third_party_count", str(pkg["third_party_count"]))
    if pkg.get("system_count"):
        t.add_row("  system_count", str(pkg["system_count"]))
    if pkg.get("disabled_count"):
        t.add_row("  disabled_count", str(pkg["disabled_count"]))
    if pkg.get("flagged_package_names"):
        t.add_row("  [red]flagged_packages[/red]", ", ".join(pkg["flagged_package_names"]))

    t.add_row("── Processes ──", "")
    if proc.get("total_processes"):
        t.add_row("  total_processes", str(proc["total_processes"]))

    console.print(t)


def _display_apk_result(app_info) -> None:  # type: ignore
    table = Table(title=f"APK Analysis: {app_info.package_name}", box=box.ROUNDED)
    table.add_column("Property", style="bold")
    table.add_column("Value")

    table.add_row("Package", app_info.package_name)
    table.add_row("Version", app_info.version_name)
    table.add_row("Target SDK", str(app_info.target_sdk))
    table.add_row("Min SDK", str(app_info.min_sdk))
    table.add_row("Debuggable", "[red]Yes[/red]" if app_info.is_debuggable else "No")
    table.add_row("Backup Allowed", "Yes" if app_info.is_backup_allowed else "No")
    table.add_row("Has Native Code", "Yes" if app_info.has_native_code else "No")
    table.add_row(
        "Dynamic Code Loading", "[yellow]Yes[/yellow]" if app_info.has_dynamic_code else "No"
    )
    table.add_row("Total Permissions", str(app_info.total_permissions))
    table.add_row(
        "Dangerous Permissions", f"[yellow]{len(app_info.dangerous_permissions)}[/yellow]"
    )
    table.add_row("Exported Components", str(len(app_info.exported_components)))
    table.add_row(
        "Open (Unprotected) Components",
        f"[red]{len(app_info.open_components)}[/red]" if app_info.open_components else "0",
    )
    table.add_row("Trackers", ", ".join(app_info.trackers[:5]) if app_info.trackers else "None")
    table.add_row("Embedded URLs", str(len(app_info.embedded_urls)))
    table.add_row("Embedded IPs", str(len(app_info.embedded_ips)))

    if app_info.certificate:
        c = app_info.certificate
        table.add_row("Certificate Issuer", c.issuer[:50] if c.issuer else "Unknown")
        table.add_row("Self-Signed", "[yellow]Yes[/yellow]" if c.is_self_signed else "No")
        table.add_row("Debug Certificate", "[red]Yes[/red]" if c.is_debug else "No")

    console.print(table)

    if app_info.dangerous_permissions:
        ptable = Table(title="Dangerous Permissions", box=box.SIMPLE)
        ptable.add_column("Permission", min_width=50)
        for p in app_info.dangerous_permissions:
            ptable.add_row(f"[yellow]{p.name}[/yellow]")
        console.print(ptable)

    if app_info.exported_components:
        ctable = Table(title="Exported Components", box=box.SIMPLE)
        ctable.add_column("Name", min_width=40)
        ctable.add_column("Type", width=12)
        ctable.add_column("Protected", width=10)
        for c in app_info.exported_components:
            prot = "[green]Yes[/green]" if c.is_protected else "[red]No[/red]"
            ctable.add_row(c.name, c.component_type.value, prot)
        console.print(ctable)


# ──────────────────────────────────────────────────────────
#  Action dispatcher
# ──────────────────────────────────────────────────────────

ACTIONS = {
    "scan_quick": action_scan_quick,
    "scan_full": action_scan_full,
    "scan_deep": action_scan_deep,
    "scan_package": action_scan_package,
    "analyze_apk": action_analyze_apk,
    "hunt": action_hunt,
    "detect_root": action_detect_root,
    "analyze_boot": action_analyze_boot,
    "check_filesystem": action_check_filesystem,
    "analyze_network": action_analyze_network,
    "timeline": action_timeline,
    "yara_scan": action_yara_scan,
    "monitor": action_monitor,
    "diff_scans": action_diff_scans,
    "search": action_search,
    "report": action_report,
    "list_scans": action_list_scans,
    "install_req": action_install_req,
    "doctor": action_doctor,
    "settings": action_settings,
    "exit": action_exit,
}


# ──────────────────────────────────────────────────────────
#  Main loop
# ──────────────────────────────────────────────────────────


def main() -> None:
    """Entry point for `aegis` command."""
    while True:
        try:
            print_banner()
            print_menu()
            choice = get_choice()

            if not choice.isdigit() or not (1 <= int(choice) <= len(ALL_OPTIONS)):
                console.print("[red]Invalid option. Try again.[/red]")
                press_enter()
                continue

            idx = int(choice) - 1
            _, action_key = ALL_OPTIONS[idx]
            action_func = ACTIONS.get(action_key)

            if action_func:
                action_func()
            else:
                console.print("[red]Action not implemented.[/red]")
                press_enter()

        except KeyboardInterrupt:
            console.print("\n\n[bold green]Goodbye. Stay secure.[/bold green]\n")
            break
        except SystemExit:
            break
        except Exception as e:
            console.print(f"\n[red]Error: {e}[/red]")
            import traceback

            traceback.print_exc()
            press_enter()


if __name__ == "__main__":
    main()

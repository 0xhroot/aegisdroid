"""Forensic timeline generation engine."""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any

from aegisdroid.core.domain import (
    Severity,
    TimelineEvent,
)

logger = logging.getLogger(__name__)


class TimelineEngine:
    """Generate forensic timeline from device artifacts."""

    def __init__(self, adb: Any = None) -> None:
        self._adb = adb

    async def generate_timeline(self, start: str = "", end: str = "") -> list[TimelineEvent]:
        events: list[TimelineEvent] = []
        events.extend(await self.get_boot_events())
        events.extend(await self.get_app_install_events())
        events.extend(await self.get_permission_change_events())
        events.extend(await self.get_adb_events())
        events.extend(await self.get_developer_option_events())
        events.extend(await self.get_account_events())
        events.extend(await self.get_usb_events())
        events.sort(key=lambda e: e.timestamp)
        return events

    async def get_boot_events(self) -> list[TimelineEvent]:
        if not self._adb:
            return []

        events = []
        out = await self._adb.shell("last reboot 2>/dev/null | head -20")
        if not out.strip():
            out = await self._adb.shell("dumpsys usagestats 2>/dev/null | grep -i boot | head -10")

        for line in out.strip().splitlines():
            ts = self._parse_timestamp(line)
            if ts:
                events.append(
                    TimelineEvent(
                        timestamp=ts,
                        category="boot",
                        title="System boot/reboot",
                        description=line.strip()[:200],
                        source="system_logs",
                    )
                )

        if not events:
            uptime = await self._adb.shell("uptime")
            if uptime.strip():
                events.append(
                    TimelineEvent(
                        timestamp=datetime.now().replace(tzinfo=None),
                        category="boot",
                        title="Current uptime",
                        description=uptime.strip(),
                        source="device",
                    )
                )

        return events

    async def get_app_install_events(self) -> list[TimelineEvent]:
        if not self._adb:
            return []

        events = []
        await self._adb.shell(
            "dumpsys package com.android.providers.downloads 2>/dev/null | head -50"
        )

        out2 = await self._adb.shell("ls -lt /data/app/ 2>/dev/null | head -30")
        for line in out2.strip().splitlines():
            ts = self._parse_ls_timestamp(line)
            if ts:
                events.append(
                    TimelineEvent(
                        timestamp=ts,
                        category="app_install",
                        title="App directory modified",
                        description=line.strip()[:200],
                        source="filesystem",
                    )
                )

        install_log = await self._adb.shell(
            "logcat -d -b events -t 500 2>/dev/null | grep -i 'install\\|package' | head -20"
        )
        for line in install_log.strip().splitlines():
            ts = self._parse_logcat_timestamp(line)
            if ts:
                events.append(
                    TimelineEvent(
                        timestamp=ts,
                        category="app_install",
                        title="Package event",
                        description=line.strip()[:200],
                        source="logcat_events",
                    )
                )

        return events

    async def get_permission_change_events(self) -> list[TimelineEvent]:
        if not self._adb:
            return []

        events = []
        out = await self._adb.shell(
            "logcat -d -b events -t 1000 2>/dev/null | grep -i 'permission' | head -20"
        )
        for line in out.strip().splitlines():
            ts = self._parse_logcat_timestamp(line)
            if ts:
                events.append(
                    TimelineEvent(
                        timestamp=ts,
                        category="permission_change",
                        title="Permission event",
                        description=line.strip()[:200],
                        source="logcat_events",
                        severity=Severity.INFO,
                    )
                )

        return events

    async def get_adb_events(self) -> list[TimelineEvent]:
        if not self._adb:
            return []

        events = []
        out = await self._adb.shell(
            "logcat -d -b events -t 1000 2>/dev/null | grep -i 'adb' | head -20"
        )
        for line in out.strip().splitlines():
            ts = self._parse_logcat_timestamp(line)
            if ts:
                events.append(
                    TimelineEvent(
                        timestamp=ts,
                        category="adb",
                        title="ADB authorization event",
                        description=line.strip()[:200],
                        source="logcat_events",
                        severity=Severity.MEDIUM,
                    )
                )

        return events

    async def get_developer_option_events(self) -> list[TimelineEvent]:
        if not self._adb:
            return []

        events = []
        dev_settings = [
            ("settings get global adb_enabled", "USB Debugging"),
            ("settings get global development_settings_enabled", "Developer Options"),
            ("settings get global adb_wifi_enabled", "ADB over WiFi"),
        ]

        for cmd, name in dev_settings:
            out = await self._adb.shell(cmd)
            value = out.strip()
            if value and value != "null":
                events.append(
                    TimelineEvent(
                        timestamp=datetime.now().replace(tzinfo=None),
                        category="developer_settings",
                        title=f"{name}: {value}",
                        description=f"Developer setting {name} is set to {value}",
                        source="device_settings",
                        severity=Severity.MEDIUM if value == "1" else Severity.INFO,
                    )
                )

        return events

    async def get_account_events(self) -> list[TimelineEvent]:
        if not self._adb:
            return []

        events = []
        out = await self._adb.shell("dumpsys account 2>/dev/null | head -30")
        if out.strip():
            accounts = []
            for line in out.strip().splitlines():
                if "Account {" in line:
                    accounts.append(line.strip())

            if accounts:
                events.append(
                    TimelineEvent(
                        timestamp=datetime.now().replace(tzinfo=None),
                        category="accounts",
                        title=f"Configured accounts ({len(accounts)})",
                        description="\n".join(accounts[:10]),
                        source="account_service",
                    )
                )

        return events

    async def get_usb_events(self) -> list[TimelineEvent]:
        if not self._adb:
            return []

        events = []
        out = await self._adb.shell(
            "logcat -d -b events -t 1000 2>/dev/null | grep -i usb | head -20"
        )
        for line in out.strip().splitlines():
            ts = self._parse_logcat_timestamp(line)
            if ts:
                events.append(
                    TimelineEvent(
                        timestamp=ts,
                        category="usb",
                        title="USB event",
                        description=line.strip()[:200],
                        source="logcat_events",
                    )
                )

        return events

    async def get_root_events(self) -> list[TimelineEvent]:
        if not self._adb:
            return []

        events = []
        indicators = [
            ("ls /data/adb/magisk", "Magisk installation"),
            ("ls /data/adb/modules", "Root modules"),
            ("which su", "Su binary"),
        ]

        for cmd, title in indicators:
            out = await self._adb.shell(cmd)
            if out.strip() and "No such file" not in out:
                events.append(
                    TimelineEvent(
                        timestamp=datetime.now().replace(tzinfo=None),
                        category="root",
                        title=title,
                        description=f"Root indicator: {out.strip()[:100]}",
                        source="filesystem",
                        severity=Severity.HIGH,
                    )
                )

        return events

    def _parse_timestamp(self, text: str) -> datetime | None:
        patterns = [
            r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
            r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})",
            r"(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})",
        ]
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                try:
                    ts_str = match.group(1)
                    for fmt in ["%b %d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%m-%d %H:%M:%S"]:
                        try:
                            return datetime.strptime(ts_str, fmt)
                        except ValueError:
                            continue
                except Exception:
                    pass
        return None

    def _parse_logcat_timestamp(self, line: str) -> datetime | None:
        match = re.search(r"(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)", line)
        if match:
            try:
                year = datetime.now().year
                ts_str = f"{year}-{match.group(1)[:5]} {match.group(1)[6:]}"
                return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S.%f")
            except Exception:
                pass
        return None

    def _parse_ls_timestamp(self, line: str) -> datetime | None:
        match = re.search(r"(\w{3})\s+(\d{1,2})\s+(\d{2}:\d{2}|\d{4})\s+(.+)", line)
        if match:
            try:
                month = match.group(1)
                day = int(match.group(2))
                time_or_year = match.group(3)
                year = datetime.now().year
                if ":" in time_or_year:
                    ts_str = f"{year} {month} {day} {time_or_year}"
                    return datetime.strptime(ts_str, "%Y %b %d %H:%M")
                ts_str = f"{time_or_year} {month} {day}"
                return datetime.strptime(ts_str, "%Y %b %d")
            except Exception:
                pass
        return None

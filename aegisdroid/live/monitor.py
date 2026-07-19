"""Live device monitoring engine."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from typing import Any

from aegisdroid.core.config import LiveMonitorConfig
from aegisdroid.core.events import Event, Events, event_bus

logger = logging.getLogger(__name__)


class LiveMonitor:
    """Continuous device monitoring with alerting."""

    def __init__(self, adb: Any = None, config: LiveMonitorConfig | None = None) -> None:
        self._adb = adb
        self._config = config or LiveMonitorConfig()
        self._running = False
        self._baseline: dict[str, Any] = {}
        self._alerts: list[dict[str, Any]] = []

    async def start(self) -> None:
        self._running = True
        logger.info("Live monitor started (interval: %.1fs)", self._config.poll_interval)

        if self._adb:
            await self._capture_baseline()

        while self._running:
            try:
                await self._tick()
            except Exception as e:
                logger.exception("Monitor tick error: %s", e)
            await asyncio.sleep(self._config.poll_interval)

    async def stop(self) -> None:
        self._running = False
        logger.info("Live monitor stopped")

    async def _tick(self) -> None:
        if not self._adb or not self._adb.is_connected:
            return

        await event_bus.publish(
            Event(
                name=Events.LIVE_MONITOR_TICK,
                data={"timestamp": datetime.now().replace(tzinfo=None).isoformat()},
                source="live_monitor",
            )
        )

        if self._config.alert_on_new_app:
            await self._check_new_apps()
        if self._config.alert_on_permission_change:
            await self._check_permissions()
        if self._config.alert_on_usb_debugging:
            await self._check_usb_debugging()
        if self._config.alert_on_accessibility:
            await self._check_accessibility()
        if self._config.alert_on_network_change:
            await self._check_network()

    async def _capture_baseline(self) -> None:
        if not self._adb:
            return
        try:
            packages = await self._adb.get_installed_packages()
            self._baseline["packages"] = packages
            self._baseline["accessibility"] = await self._adb.get_accessibility_services()

            usb = await self._adb.shell("settings get global adb_enabled")
            self._baseline["usb_debugging"] = usb.strip()

            dev = await self._adb.shell("settings get global development_settings_enabled")
            self._baseline["developer_options"] = dev.strip()
        except Exception as e:
            logger.exception("Baseline capture failed: %s", e)

    async def _check_new_apps(self) -> None:
        if not self._adb:
            return
        current = await self._adb.get_installed_packages()
        baseline = set(self._baseline.get("packages", []))
        new_apps = set(current) - baseline

        for pkg in new_apps:
            alert = {
                "type": "new_app",
                "package": pkg,
                "timestamp": datetime.now().replace(tzinfo=None).isoformat(),
                "severity": "medium",
            }
            self._alerts.append(alert)
            await event_bus.publish(
                Event(
                    name=Events.APP_INSTALLED,
                    data=alert,
                    source="live_monitor",
                )
            )
            logger.warning("New app detected: %s", pkg)

        self._baseline["packages"] = current

    async def _check_permissions(self) -> None:
        pass

    async def _check_usb_debugging(self) -> None:
        if not self._adb:
            return
        current = await self._adb.shell("settings get global adb_enabled")
        baseline_val = self._baseline.get("usb_debugging", "")
        if current.strip() != baseline_val:
            alert = {
                "type": "usb_debugging_changed",
                "old": baseline_val,
                "new": current.strip(),
                "timestamp": datetime.now().replace(tzinfo=None).isoformat(),
                "severity": "high",
            }
            self._alerts.append(alert)
            self._baseline["usb_debugging"] = current.strip()
            await event_bus.publish(
                Event(
                    name=Events.USB_DEBUGGING_CHANGED,
                    data=alert,
                    source="live_monitor",
                )
            )

    async def _check_accessibility(self) -> None:
        if not self._adb:
            return
        current = await self._adb.get_accessibility_services()
        baseline_val = self._baseline.get("accessibility", [])
        new_services = set(current) - set(baseline_val)

        for svc in new_services:
            alert = {
                "type": "accessibility_service_added",
                "service": svc,
                "timestamp": datetime.now().replace(tzinfo=None).isoformat(),
                "severity": "high",
            }
            self._alerts.append(alert)
            await event_bus.publish(
                Event(
                    name=Events.ACCESSIBILITY_CHANGED,
                    data=alert,
                    source="live_monitor",
                )
            )

        self._baseline["accessibility"] = current

    async def _check_network(self) -> None:
        pass

    def get_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._alerts[-limit:]

    @property
    def is_running(self) -> bool:
        return self._running

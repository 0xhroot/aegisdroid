"""Event bus for decoupled component communication."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)

EventHandler = Callable[["Event"], Coroutine[Any, Any, None]]


@dataclass
class Event:
    name: str
    data: dict[str, Any] = field(default_factory=dict)
    source: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now().replace(tzinfo=None))
    id: str = field(default_factory=lambda: str(uuid4()))


class EventBus:
    """Async publish-subscribe event bus."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[EventHandler]] = defaultdict(list)
        self._history: list[Event] = []
        self._max_history = 1000

    def subscribe(self, event_name: str, handler: EventHandler) -> None:
        self._handlers[event_name].append(handler)

    def unsubscribe(self, event_name: str, handler: EventHandler) -> None:
        if handler in self._handlers[event_name]:
            self._handlers[event_name].remove(handler)

    async def publish(self, event: Event) -> None:
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history :]

        handlers = self._handlers.get(event.name, [])
        wildcard_handlers = self._handlers.get("*", [])

        for handler in handlers + wildcard_handlers:
            try:
                await handler(event)
            except Exception as e:
                logger.exception("Event handler error for '%s': %s", event.name, e)

    def get_history(self, event_name: str | None = None, limit: int = 100) -> list[Event]:
        events = self._history
        if event_name:
            events = [e for e in events if e.name == event_name]
        return events[-limit:]


# Global event bus instance
event_bus = EventBus()


# Standard event names
class Events:
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    FINDING_DETECTED = "finding.detected"
    THREAT_ALERT = "threat.alert"
    DEVICE_CONNECTED = "device.connected"
    DEVICE_DISCONNECTED = "device.disconnected"
    PLUGIN_LOADED = "plugin.loaded"
    PLUGIN_UNLOADED = "plugin.unloaded"
    REPORT_GENERATED = "report.generated"
    LIVE_MONITOR_TICK = "live.monitor.tick"
    APP_INSTALLED = "app.installed"
    APP_REMOVED = "app.removed"
    PERMISSION_CHANGED = "permission.changed"
    CERTIFICATE_CHANGED = "certificate.changed"
    NETWORK_CHANGED = "network.changed"
    USB_DEBUGGING_CHANGED = "usb_debugging.changed"
    DEVELOPER_SETTINGS_CHANGED = "developer_settings.changed"
    ACCESSIBILITY_CHANGED = "accessibility.changed"
    OVERLAY_CHANGED = "overlay.changed"
    VPN_CHANGED = "vpn.changed"
    TIMELINE_EVENT = "timeline.event"
    YARA_MATCH = "yara.match"
    RULE_TRIGGERED = "rule.triggered"

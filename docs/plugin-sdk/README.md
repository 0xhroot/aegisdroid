# Plugin SDK

## Overview

AegisDroid supports plugins for extending analysis capabilities without modifying core code.

## Plugin Structure

```
plugins/
├── my_scanner/
│   ├── __init__.py
│   └── scanner.py
└── my_reporter/
    ├── __init__.py
    └── reporter.py
```

## Writing a Plugin

```python
# plugins/my_scanner/scanner.py
from aegisdroid.core.events import event_bus, Events
from aegisdroid.core.domain import Finding, Severity, ThreatCategory

async def on_scan_started(event):
    """Hook into scan start."""
    print(f"Custom analysis starting for: {event.data}")

async def on_scan_completed(event):
    """Hook into scan completion."""
    print(f"Scan completed: {event.data}")

# Register handlers
event_bus.subscribe(Events.SCAN_STARTED, on_scan_started)
event_bus.subscribe(Events.SCAN_COMPLETED, on_scan_completed)
```

## Plugin Lifecycle

1. **Discovery** — Scan `plugins/` directory for Python modules
2. **Loading** — Dynamic import of plugin module
3. **Registration** — Plugin registers handlers with the event bus
4. **Execution** — Plugin hooks fire during scan pipeline
5. **Teardown** — Cleanup resources after scan completes

## Available Events

| Event | When | Data |
|-------|------|------|
| `SCAN_STARTED` | Scan begins | scan_type, package |
| `SCAN_COMPLETED` | Scan ends | scan_id, findings, threat_score |
| `SCAN_FAILED` | Scan errors | error |
| `DEVICE_CONNECTED` | Device connected | serial |
| `DEVICE_DISCONNECTED` | Device lost | serial |
| `FINDING_DETECTED` | New finding | finding data |

## Distribution

Plugins can be distributed as:

1. **Local modules** — Place in `plugins/` directory
2. **Python packages** — Install via pip
3. **Entry points** — Register via `pyproject.toml`:
   ```toml
   [project.entry-points."aegisdroid.plugins"]
   my_scanner = "my_scanner:register"
   ```

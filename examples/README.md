# Example: Basic Scan

```python
"""Example: Run a full device scan programmatically."""

import asyncio
from aegisdroid.scanner.engine import Scanner
from aegisdroid.core.config import load_config

async def main():
    config = load_config()
    scanner = Scanner(config)

    # Connect to device
    connected = await scanner.adb.connect()
    if not connected:
        print("No device connected")
        return

    # Run full scan
    result = await scanner.full_scan()

    # Print results
    print(f"Threat Score: {result.threat_confidence_score:.0%}")
    print(f"Findings: {len(result.findings)}")

    for finding in result.findings:
        print(f"  [{finding.severity.value.upper()}] {finding.title}")

asyncio.run(main())
```

# Example: APK Analysis

```python
"""Example: Analyze a local APK file."""

import asyncio
from aegisdroid.apk.analyzer import APKAnalyzer

async def main():
    analyzer = APKAnalyzer()
    app_info = await analyzer.analyze("/path/to/app.apk")

    print(f"Package: {app_info.package_name}")
    print(f"Version: {app_info.version_name}")
    print(f"Permissions: {app_info.total_permissions}")
    print(f"Dangerous: {len(app_info.dangerous_permissions)}")
    print(f"Trackers: {app_info.trackers}")

asyncio.run(main())
```

# Example: YARA Scanning

```python
"""Example: YARA scan a directory."""

import asyncio
from aegisdroid.yara.engine import YaraEngine

async def main():
    engine = YaraEngine("rules/packs")
    matches = await engine.scan_directory("/data/local/tmp/")

    for match in matches:
        print(f"Rule: {match.rule_name}")
        print(f"File: {match.file_path}")
        print(f"Description: {match.description}")

asyncio.run(main())
```

# Example: Custom Plugin

```python
"""Example: Custom analysis plugin."""

from aegisdroid.core.events import event_bus, Events

async def my_handler(event):
    print(f"Event: {event.name}")
    print(f"Data: {event.data}")

event_bus.subscribe(Events.SCAN_COMPLETED, my_handler)
```

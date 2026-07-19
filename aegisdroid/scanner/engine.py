"""Scanner engine - orchestrates all analysis components."""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from aegisdroid.adb.adapter import ADBAdapter
from aegisdroid.apk.analyzer import APKAnalyzer
from aegisdroid.core.config import AegisConfig
from aegisdroid.core.domain import (
    AppInfo,
    Evidence,
    EvidenceType,
    Finding,
    ScanResult,
    ScanType,
    Severity,
    ThreatCategory,
)
from aegisdroid.core.events import Event, Events, event_bus
from aegisdroid.forensics.filesystem import FilesystemForensics
from aegisdroid.forensics.network import NetworkAnalyzer
from aegisdroid.forensics.profiler import DeviceProfiler
from aegisdroid.rules.engine import RuleEngine
from aegisdroid.threats.backdoor_detector import BackdoorDetector
from aegisdroid.threats.boot_analyzer import BootAnalyzer
from aegisdroid.threats.detector import ThreatDetector
from aegisdroid.threats.malware_scanner import MalwareScanner
from aegisdroid.threats.root_detector import RootDetector
from aegisdroid.timeline.engine import TimelineEngine
from aegisdroid.yara.engine import YaraEngine

logger = logging.getLogger(__name__)


class Scanner:
    """Main scanner orchestrator."""

    def __init__(self, config: AegisConfig | None = None) -> None:
        self._config = config or AegisConfig()
        self._adb = ADBAdapter(self._config.adb)
        self._apk_analyzer = APKAnalyzer()
        self._threat_detector = ThreatDetector()
        self._root_detector = RootDetector(self._adb)
        self._boot_analyzer = BootAnalyzer(self._adb)
        self._fs_forensics = FilesystemForensics(self._adb)
        self._network_analyzer = NetworkAnalyzer(self._adb)
        self._profiler = DeviceProfiler(self._adb)
        self._malware_scanner = MalwareScanner(self._adb)
        self._backdoor_detector = BackdoorDetector(self._adb)
        self._timeline = TimelineEngine(self._adb)
        self._yara_engine = YaraEngine(self._config.yara.effective_rules_dir)
        self._rule_engine = RuleEngine()
        self._app_info: AppInfo | None = None

    @property
    def adb(self) -> ADBAdapter:
        return self._adb

    async def quick_scan(self, package: str = "") -> ScanResult:
        return await self._scan(ScanType.QUICK, package)

    async def full_scan(self, package: str = "") -> ScanResult:
        return await self._scan(ScanType.FULL, package)

    async def deep_scan(self, package: str = "") -> ScanResult:
        return await self._scan(ScanType.DEEP, package)

    async def target_scan(self, package: str) -> ScanResult:
        return await self._scan(ScanType.TARGETED, package)

    async def _scan(self, scan_type: ScanType, package: str = "") -> ScanResult:
        scan_result = ScanResult(
            scan_type=scan_type,
            device_serial=self._adb.current_serial,
            package_name=package,
            started_at=datetime.now().replace(tzinfo=None),
        )

        await event_bus.publish(
            Event(
                name=Events.SCAN_STARTED,
                data={"scan_type": scan_type.value, "package": package},
                source="scanner",
            )
        )

        try:
            connected = await self._adb.connect()
            if not connected:
                scan_result.error = "No device connected"
                scan_result.completed_at = datetime.now().replace(tzinfo=None)
                return scan_result

            if scan_type == ScanType.QUICK:
                await self._quick_analysis(scan_result, package)
            elif scan_type == ScanType.FULL:
                await self._full_analysis(scan_result, package)
            elif scan_type == ScanType.DEEP:
                await self._deep_analysis(scan_result, package)
            elif scan_type == ScanType.TARGETED:
                await self._targeted_analysis(scan_result, package)

            custom_rules = await self._rule_engine.load_rules(
                str(Path(__file__).parent.parent / "rules")
            )
            if custom_rules:
                rule_findings = await self._rule_engine.evaluate(scan_result, custom_rules)
                scan_result.findings.extend(rule_findings)

            scan_result.completed_at = datetime.now().replace(tzinfo=None)

            await event_bus.publish(
                Event(
                    name=Events.SCAN_COMPLETED,
                    data={
                        "scan_id": scan_result.id,
                        "findings": len(scan_result.findings),
                        "threat_score": scan_result.threat_confidence_score,
                    },
                    source="scanner",
                )
            )

        except Exception as e:
            logger.exception("Scan failed: %s", e)
            scan_result.error = str(e)
            scan_result.completed_at = datetime.now().replace(tzinfo=None)

            await event_bus.publish(
                Event(
                    name=Events.SCAN_FAILED,
                    data={"error": str(e)},
                    source="scanner",
                )
            )

        return scan_result

    async def _quick_analysis(self, result: ScanResult, package: str) -> None:
        device_info = await self._adb.get_device_info()
        result.metadata["device"] = device_info.__dict__

        if package:
            await self._analyze_package(result, package)

        root_findings = await self._root_detector.detect(device_info)
        result.findings.extend(root_findings)

        malware_findings = await self._malware_scanner.scan()
        result.findings.extend(malware_findings)

    async def _full_analysis(self, result: ScanResult, package: str) -> None:
        device_info = await self._adb.get_device_info()
        result.metadata["device"] = device_info.__dict__

        with open("/tmp/_aegis_device_profile.json", "w") as f:
            import json

            profile = await self._profiler.profile_device()
            result.metadata["device_profile"] = profile
            json.dump(profile, f, indent=2, default=str)

        if package:
            await self._analyze_package(result, package)

        root_findings = await self._root_detector.detect(device_info)
        result.findings.extend(root_findings)

        boot_findings = await self._boot_analyzer.detect_boot_findings()
        result.findings.extend(boot_findings)

        fs_findings = await self._fs_forensics.find_suspicious_files()
        result.findings.extend(fs_findings)

        net_findings = await self._network_analyzer.detect_network_findings()
        result.findings.extend(net_findings)

        malware_findings = await self._malware_scanner.scan()
        result.findings.extend(malware_findings)

        backdoor_findings = await self._backdoor_detector.scan()
        result.findings.extend(backdoor_findings)

        timeline = await self._timeline.generate_timeline()
        result.metadata["timeline_events"] = [
            {"title": e.title, "category": e.category, "timestamp": e.timestamp.isoformat()}
            for e in timeline
        ]

    async def _deep_analysis(self, result: ScanResult, package: str) -> None:
        await self._full_analysis(result, package)

        suid_findings = await self._fs_forensics.find_suid_files()
        result.findings.extend(suid_findings)

        if package:
            apk_path = await self._adb.get_package_path(package)
            if apk_path:
                local_path = f"/tmp/_aegis_{package.replace('.', '_')}.apk"
                pulled = await self._adb.pull(apk_path, local_path)
                if pulled:
                    yara_matches = await self._yara_engine.scan_apk(local_path)
                    for match in yara_matches:
                        result.findings.append(
                            Finding(
                                category=ThreatCategory.CUSTOM,
                                severity=Severity.HIGH,
                                title=f"YARA match: {match.rule_name}",
                                description=match.description
                                or f"YARA rule '{match.rule_name}' matched",
                                evidence=[
                                    Evidence(
                                        type=EvidenceType.YARA,
                                        source="yara_engine",
                                        description=f"Rule: {match.rule_name} in {match.file_path}",
                                        confidence=0.9,
                                    )
                                ],
                                confidence=0.9,
                            )
                        )

    async def _targeted_analysis(self, result: ScanResult, package: str) -> None:
        if package:
            await self._analyze_package(result, package)

    async def _analyze_package(self, result: ScanResult, package: str) -> None:
        apk_path = await self._adb.get_package_path(package)
        if not apk_path:
            result.error = f"Package not found: {package}"
            return

        local_path = f"/tmp/_aegis_{package.replace('.', '_')}.apk"
        pulled = await self._adb.pull(apk_path, local_path)
        if not pulled:
            result.error = f"Failed to pull APK: {apk_path}"
            return

        app_info = await self._apk_analyzer.analyze(local_path)
        self._app_info = app_info

        result.metadata["package"] = app_info.package_name
        result.metadata["version"] = app_info.version_name
        result.metadata["permissions"] = [p.name for p in app_info.permissions]
        result.metadata["exported_components"] = [c.name for c in app_info.exported_components]

        findings = await self._threat_detector.analyze(result, app_info)
        result.findings.extend(findings)

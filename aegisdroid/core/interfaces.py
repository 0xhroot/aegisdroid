"""Core interfaces (ports) for hexagonal architecture."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegisdroid.core.domain import (
        AppInfo,
        CertificateInfo,
        ComponentInfo,
        DeviceInfo,
        Finding,
        Hash,
        NetworkConnection,
        PermissionInfo,
        PluginMetadata,
        ScanResult,
        TimelineEvent,
        YaraMatch,
    )


class ADBPort(ABC):
    """Port for Android Debug Bridge communication."""

    @abstractmethod
    async def connect(self, serial: str = "") -> bool: ...

    @abstractmethod
    async def disconnect(self) -> None: ...

    @abstractmethod
    async def execute(self, command: str, timeout: float = 30.0) -> tuple[int, str, str]: ...

    @abstractmethod
    async def shell(self, command: str, timeout: float = 30.0) -> str: ...

    @abstractmethod
    async def pull(self, remote: str, local: str) -> bool: ...

    @abstractmethod
    async def push(self, local: str, remote: str) -> bool: ...

    @abstractmethod
    async def list_devices(self) -> list[dict[str, str]]: ...

    @abstractmethod
    async def get_device_info(self) -> DeviceInfo: ...

    @abstractmethod
    async def get_property(self, prop: str) -> str: ...

    @abstractmethod
    async def is_rooted(self) -> bool: ...

    @abstractmethod
    async def get_installed_packages(self) -> list[str]: ...

    @abstractmethod
    async def get_package_path(self, package: str) -> str: ...

    @abstractmethod
    async def dumpsys(self, service: str) -> str: ...

    @abstractmethod
    async def get_logcat(self, buffer: str = "main", lines: int = 1000) -> str: ...

    @abstractmethod
    async def run_as(self, package: str, command: str) -> str: ...


class APKAnalysisPort(ABC):
    """Port for APK static analysis."""

    @abstractmethod
    async def analyze(self, apk_path: str) -> AppInfo: ...

    @abstractmethod
    async def extract_manifest(self, apk_path: str) -> dict[str, Any]: ...

    @abstractmethod
    async def get_permissions(self, apk_path: str) -> list[PermissionInfo]: ...

    @abstractmethod
    async def get_components(self, apk_path: str) -> list[ComponentInfo]: ...

    @abstractmethod
    async def get_certificate(self, apk_path: str) -> CertificateInfo | None: ...

    @abstractmethod
    async def get_native_libs(self, apk_path: str) -> list[str]: ...

    @abstractmethod
    async def find_strings(self, apk_path: str, pattern: str) -> list[str]: ...

    @abstractmethod
    async def analyze_dex(self, apk_path: str) -> dict[str, Any]: ...

    @abstractmethod
    async def detect_trackers(self, apk_path: str) -> list[str]: ...

    @abstractmethod
    async def generate_sbom(self, apk_path: str) -> dict[str, Any]: ...


class ThreatDetectionPort(ABC):
    """Port for threat detection engine."""

    @abstractmethod
    async def analyze(
        self, scan_result: ScanResult, app_info: AppInfo | None = None
    ) -> list[Finding]: ...

    @abstractmethod
    async def calculate_threat_score(self, findings: list[Finding]) -> float: ...

    @abstractmethod
    async def correlate(self, findings: list[Finding]) -> list[Finding]: ...

    @abstractmethod
    async def explain(self, finding: Finding) -> str: ...


class RootDetectionPort(ABC):
    """Port for root detection."""

    @abstractmethod
    async def detect(self, device: DeviceInfo) -> list[Finding]: ...

    @abstractmethod
    async def detect_magisk(self) -> list[Finding]: ...

    @abstractmethod
    async def detect_kernelsu(self) -> list[Finding]: ...

    @abstractmethod
    async def detect_apatch(self) -> list[Finding]: ...

    @abstractmethod
    async def detect_frida(self) -> list[Finding]: ...

    @abstractmethod
    async def detect_xposed(self) -> list[Finding]: ...

    @abstractmethod
    async def detect_hooking_frameworks(self) -> list[Finding]: ...


class BootAnalysisPort(ABC):
    """Port for boot chain analysis."""

    @abstractmethod
    async def analyze_boot(self) -> dict[str, Any]: ...

    @abstractmethod
    async def analyze_vbmeta(self) -> dict[str, Any]: ...

    @abstractmethod
    async def check_avb(self) -> dict[str, Any]: ...

    @abstractmethod
    async def check_dm_verity(self) -> dict[str, Any]: ...

    @abstractmethod
    async def get_rollback_index(self) -> int: ...


class FilesystemForensicsPort(ABC):
    """Port for filesystem integrity analysis."""

    @abstractmethod
    async def compute_hashes(self, paths: list[str]) -> dict[str, Hash]: ...

    @abstractmethod
    async def detect_modifications(self, baseline_path: str) -> list[Finding]: ...

    @abstractmethod
    async def find_suspicious_files(self) -> list[Finding]: ...

    @abstractmethod
    async def analyze_permissions_map(self) -> dict[str, Any]: ...


class NetworkAnalysisPort(ABC):
    """Port for network intelligence."""

    @abstractmethod
    async def analyze_connections(self) -> list[NetworkConnection]: ...

    @abstractmethod
    async def analyze_dns(self) -> list[dict[str, Any]]: ...

    @abstractmethod
    async def analyze_vpn(self) -> dict[str, Any]: ...

    @abstractmethod
    async def check_domain_reputation(self, domain: str) -> float: ...

    @abstractmethod
    async def check_ip_reputation(self, ip: str) -> float: ...

    @abstractmethod
    async def build_connection_graph(self) -> dict[str, Any]: ...


class TimelinePort(ABC):
    """Port for forensic timeline generation."""

    @abstractmethod
    async def generate_timeline(self, start: str = "", end: str = "") -> list[TimelineEvent]: ...

    @abstractmethod
    async def get_boot_events(self) -> list[TimelineEvent]: ...

    @abstractmethod
    async def get_app_install_events(self) -> list[TimelineEvent]: ...

    @abstractmethod
    async def get_permission_change_events(self) -> list[TimelineEvent]: ...

    @abstractmethod
    async def get_adb_events(self) -> list[TimelineEvent]: ...


class YaraPort(ABC):
    """Port for YARA rule scanning."""

    @abstractmethod
    async def scan_file(self, file_path: str, rules_path: str = "") -> list[YaraMatch]: ...

    @abstractmethod
    async def scan_directory(self, dir_path: str, rules_path: str = "") -> list[YaraMatch]: ...

    @abstractmethod
    async def scan_apk(self, apk_path: str, rules_path: str = "") -> list[YaraMatch]: ...

    @abstractmethod
    async def compile_rules(self, rules_path: str) -> Any: ...

    @abstractmethod
    async def list_rules(self, rules_path: str) -> list[str]: ...


class RuleEnginePort(ABC):
    """Port for custom rule evaluation."""

    @abstractmethod
    async def load_rules(self, rules_path: str) -> list[dict[str, Any]]: ...

    @abstractmethod
    async def evaluate(
        self, scan_result: ScanResult, rules: list[dict[str, Any]]
    ) -> list[Finding]: ...

    @abstractmethod
    async def validate_rule(self, rule: dict[str, Any]) -> bool: ...


class ReportPort(ABC):
    """Port for report generation."""

    @abstractmethod
    async def generate(
        self,
        scan_result: ScanResult,
        format: str = "markdown",
        output_path: str = "",
    ) -> str: ...

    @abstractmethod
    async def generate_executive_summary(self, scan_result: ScanResult) -> str: ...

    @abstractmethod
    async def generate_sarif(self, scan_result: ScanResult) -> dict[str, Any]: ...


class DatabasePort(ABC):
    """Port for data persistence."""

    @abstractmethod
    async def initialize(self) -> None: ...

    @abstractmethod
    async def save_scan(self, scan_result: ScanResult) -> str: ...

    @abstractmethod
    async def get_scan(self, scan_id: str) -> ScanResult | None: ...

    @abstractmethod
    async def list_scans(self, limit: int = 50) -> list[ScanResult]: ...

    @abstractmethod
    async def save_baseline(self, device_serial: str, data: dict[str, Any]) -> None: ...

    @abstractmethod
    async def get_baseline(self, device_serial: str) -> dict[str, Any] | None: ...

    @abstractmethod
    async def save_timeline_event(self, event: TimelineEvent) -> None: ...

    @abstractmethod
    async def get_timeline(self, limit: int = 100) -> list[TimelineEvent]: ...


class AIAssistPort(ABC):
    """Port for AI-assisted analysis."""

    @abstractmethod
    async def explain_finding(self, finding: Finding) -> str: ...

    @abstractmethod
    async def generate_report(self, scan_result: ScanResult) -> str: ...

    @abstractmethod
    async def suggest_remediation(self, findings: list[Finding]) -> list[str]: ...

    @abstractmethod
    async def natural_language_query(self, query: str, context: dict[str, Any]) -> str: ...


class PluginPort(ABC):
    """Port for plugin management."""

    @abstractmethod
    async def discover_plugins(self) -> list[PluginMetadata]: ...

    @abstractmethod
    async def load_plugin(self, name: str) -> Any: ...

    @abstractmethod
    async def register_command(self, name: str, handler: Any) -> None: ...

    @abstractmethod
    async def register_scanner(self, name: str, scanner: Any) -> None: ...

    @abstractmethod
    async def register_rule(self, name: str, rule: Any) -> None: ...

    @abstractmethod
    async def get_plugin(self, name: str) -> Any: ...

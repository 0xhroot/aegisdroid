"""Core domain models for AegisDroid."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

# ──────────────────────────────────────────────
#  Enums
# ──────────────────────────────────────────────


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NONE = "none"


class ThreatCategory(Enum):
    ROOT = "root"
    BOOT_TAMPER = "boot_tamper"
    SUSPICIOUS_PERMISSION = "suspicious_permission"
    DYNAMIC_CODE = "dynamic_code_loading"
    CRYPTO_MINING = "crypto_mining"
    DATA_EXFIL = "data_exfiltration"
    SURVEILLANCE = "surveillance"
    RANSOMWARE = "ransomware"
    BANKING_TROJAN = "banking_trojan"
    ADWARE = "adware"
    SPYWARE = "spyware"
    STALKWARE = "stalkware"
    HOOKING_FRAMEWORK = "hooking_framework"
    FRIDA = "frida"
    XPOSED = "xposed"
    OVERLAY_ATTACK = "overlay_attack"
    ACCESSIBILITY_ABUSE = "accessibility_abuse"
    SMS_FRAUD = "sms_fraud"
    WAP_BILLING = "wap_billing"
    CREDENTIAL_THEFT = "credential_theft"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    ENCRYPTION_BYPASS = "encryption_bypass"
    NETWORK_ANOMALY = "network_anomaly"
    FILESYSTEM_ANOMALY = "filesystem_anomaly"
    CERTIFICATE_ANOMALY = "certificate_anomaly"
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    POLICY_VIOLATION = "policy_violation"
    CUSTOM = "custom"
    BACKDOOR = "backdoor"


class ScanType(Enum):
    QUICK = "quick"
    FULL = "full"
    DEEP = "deep"
    TARGETED = "targeted"
    YARA = "yara"
    DIFF = "diff"


class EvidenceType(Enum):
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    BEHAVIORAL = "behavioral"
    NETWORK = "network"
    FILESYSTEM = "filesystem"
    BOOT = "boot"
    PERMISSION = "permission"
    CERTIFICATE = "certificate"
    YARA = "yara"
    HEURISTIC = "heuristic"
    IOC = "ioc"
    TIMELINE = "timeline"
    USER_OBSERVATION = "user_observation"


class ComponentType(Enum):
    ACTIVITY = "activity"
    SERVICE = "service"
    RECEIVER = "receiver"
    PROVIDER = "provider"
    PERMISSION = "permission"
    META_DATA = "meta-data"


class AppCategory(Enum):
    SYSTEM = "system"
    THIRD_PARTY = "third_party"
    PRIVILEGED = "privileged"
    UPDATED_SYSTEM = "updated_system"
    UNKNOWN = "unknown"


class DeviceState(Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    UNAUTHORIZED = "unauthorized"
    RECOVERY = "recovery"
    SIDELOAD = "sideload"
    OFFLINE = "offline"


class PersistenceMethod(Enum):
    BOOT_COMPLETED = "boot_completed"
    ALARM = "alarm"
    ACCOUNT_SYNC = "account_sync"
    ACCESSIBILITY = "accessibility"
    DEVICE_ADMIN = "device_admin"
    OVERLAY = "overlay"
    FOREGROUND_SERVICE = "foreground_service"
    NOTIFICATION_LISTENER = "notification_listener"
    INPUT_METHOD = "input_method"
    LAUNCHER = "launcher"
    WALLPAPER = "wallpaper"
    JOB_SCHEDULER = "job_scheduler"
    CONTENT_PROVIDER = "content_provider"
    BROADCAST_RECEIVER = "broadcast_receiver"
    NATIVE_DAEMON = "native_daemon"
    FRIDA_GADGET = "frida_gadget"
    UNKNOWN = "unknown"


# ──────────────────────────────────────────────
#  Core Value Objects
# ──────────────────────────────────────────────


@dataclass(frozen=True)
class Hash:
    sha256: str
    md5: str = ""
    sha1: str = ""
    ssdeep: str = ""

    @classmethod
    def from_bytes(cls, data: bytes) -> Hash:
        return cls(
            sha256=hashlib.sha256(data).hexdigest(),
            md5=hashlib.md5(data).hexdigest(),
            sha1=hashlib.sha1(data).hexdigest(),
        )

    @classmethod
    def from_file(cls, path: str) -> Hash:
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
                md5.update(chunk)
                sha1.update(chunk)
        return cls(
            sha256=sha256.hexdigest(),
            md5=md5.hexdigest(),
            sha1=sha1.hexdigest(),
        )

    def __str__(self) -> str:
        return self.sha256


@dataclass(frozen=True)
class Coordinates:
    latitude: float
    longitude: float


@dataclass(frozen=True)
class Version:
    major: int
    minor: int
    patch: int

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    @classmethod
    def parse(cls, version_str: str) -> Version:
        parts = version_str.split(".")
        return cls(
            major=int(parts[0]) if len(parts) > 0 else 0,
            minor=int(parts[1]) if len(parts) > 1 else 0,
            patch=int(parts[2]) if len(parts) > 2 else 0,
        )


@dataclass(frozen=True)
class Domain:
    name: str
    ip: str = ""
    port: int = 443
    is_https: bool = True
    country: str = ""
    asn: str = ""
    reputation: float = 0.5  # 0.0 = malicious, 1.0 = clean

    @property
    def is_suspicious(self) -> bool:
        return self.reputation < 0.3


@dataclass(frozen=True)
class IpAddress:
    address: str
    port: int = 0
    protocol: str = "tcp"
    country: str = ""
    asn: str = ""
    reverse_dns: str = ""
    reputation: float = 0.5


# ──────────────────────────────────────────────
#  Core Entities
# ──────────────────────────────────────────────


@dataclass
class Evidence:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: EvidenceType = EvidenceType.STATIC_ANALYSIS
    source: str = ""
    description: str = ""
    raw_data: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now().replace(tzinfo=None))
    confidence: float = 0.0

    @property
    def summary(self) -> str:
        return f"[{self.type.value}] {self.source}: {self.description}"


@dataclass
class Finding:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    category: ThreatCategory = ThreatCategory.BEHAVIORAL_ANOMALY
    severity: Severity = Severity.INFO
    title: str = ""
    description: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    confidence: float = 0.0
    mitigation: str = ""
    references: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now().replace(tzinfo=None))

    @property
    def risk_score(self) -> float:
        severity_map = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.3,
            Severity.INFO: 0.1,
            Severity.NONE: 0.0,
        }
        return severity_map[self.severity] * self.confidence

    def explain(self) -> str:
        lines = [
            f"Category: {self.category.value}",
            f"Severity: {self.severity.value.upper()}",
            f"Confidence: {self.confidence:.0%}",
            f"Description: {self.description}",
        ]
        if self.evidence:
            lines.append("Evidence:")
            for e in self.evidence:
                lines.append(f"  • {e.summary}")
        if self.mitigation:
            lines.append(f"Mitigation: {self.mitigation}")
        return "\n".join(lines)


@dataclass
class ScanResult:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scan_type: ScanType = ScanType.QUICK
    device_serial: str = ""
    package_name: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now().replace(tzinfo=None))
    completed_at: datetime | None = None
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    @property
    def duration(self) -> float:
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return 0.0

    @property
    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.severity, []).append(f)
        return result

    @property
    def threat_confidence_score(self) -> float:
        if not self.findings:
            return 0.0
        return sum(f.risk_score for f in self.findings) / len(self.findings)

    @property
    def total_critical(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def total_high(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def summary(self) -> str:
        tcs = self.threat_confidence_score
        counts = self.findings_by_severity
        return (
            f"Threat Confidence Score: {tcs:.0%}\n"
            f"Findings: {len(self.findings)} total "
            f"({len(counts.get(Severity.CRITICAL, []))} critical, "
            f"{len(counts.get(Severity.HIGH, []))} high, "
            f"{len(counts.get(Severity.MEDIUM, []))} medium, "
            f"{len(counts.get(Severity.LOW, []))} low)"
        )


@dataclass
class DeviceInfo:
    serial: str = ""
    model: str = ""
    manufacturer: str = ""
    brand: str = ""
    device: str = ""
    board: str = ""
    hardware: str = ""
    android_version: str = ""
    sdk_level: int = 0
    build_id: str = ""
    build_fingerprint: str = ""
    build_type: str = ""
    build_tags: str = ""
    security_patch: str = ""
    kernel_version: str = ""
    baseband: str = ""
    bootloader: str = ""
    serial_number: str = ""
    imei: str = ""
    mac_address: str = ""
    is_emulator: bool = False
    is_rooted: bool = False
    state: DeviceState = DeviceState.CONNECTED
    properties: dict[str, str] = field(default_factory=dict)

    @property
    def is_real_device(self) -> bool:
        return not self.is_emulator

    def fingerprint_match(self, known_good: str) -> bool:
        return self.build_fingerprint == known_good


@dataclass
class CertificateInfo:
    subject: str = ""
    issuer: str = ""
    serial: str = ""
    not_before: datetime | None = None
    not_after: datetime | None = None
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    is_self_signed: bool = False
    is_debug: bool = False
    key_size: int = 0
    key_type: str = ""
    signature_algorithm: str = ""
    chain: list[CertificateInfo] = field(default_factory=list)
    is_valid: bool = True
    validation_error: str = ""

    @property
    def is_expired(self) -> bool:
        if self.not_after:
            return datetime.now().replace(tzinfo=None) > self.not_after
        return False

    @property
    def is_weak_key(self) -> bool:
        return self.key_size < 2048


@dataclass
class PermissionInfo:
    name: str = ""
    protection_level: str = ""
    is_dangerous: bool = False
    is_custom: bool = False
    description: str = ""
    group: str = ""
    max_sdk: int = 0

    RISKY_PERMISSIONS: frozenset[str] = frozenset(
        {
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.READ_PHONE_STATE",
            "android.permission.READ_PHONE_NUMBERS",
            "android.permission.CALL_PHONE",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.READ_CALENDAR",
            "android.permission.WRITE_CALENDAR",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.READ_MEDIA_VIDEO",
            "android.permission.READ_MEDIA_AUDIO",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.BODY_SENSORS",
            "android.permission.ACTIVITY_RECOGNITION",
            "android.permission.USE_BIOMETRIC",
            "android.permission.USE_FINGERPRINT",
        }
    )

    @property
    def is_risky(self) -> bool:
        return self.name in self.RISKY_PERMISSIONS


@dataclass
class ComponentInfo:
    name: str = ""
    component_type: ComponentType = ComponentType.ACTIVITY
    exported: bool = False
    enabled: bool = True
    permission: str = ""
    intent_filters: list[dict[str, Any]] = field(default_factory=list)
    has_intent_filter: bool = False
    is_protected: bool = False
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def is_open(self) -> bool:
        return self.exported and not self.is_protected


@dataclass
class NativeLibrary:
    name: str = ""
    path: str = ""
    sha256: str = ""
    size: int = 0
    arch: str = ""
    is_stripped: bool = True
    imported_functions: list[str] = field(default_factory=list)
    suspicious_functions: list[str] = field(default_factory=list)


@dataclass
class NetworkConnection:
    domain: str = ""
    ip: str = ""
    port: int = 443
    protocol: str = "tcp"
    is_encrypted: bool = True
    first_seen: datetime = field(default_factory=lambda: datetime.now().replace(tzinfo=None))
    last_seen: datetime = field(default_factory=lambda: datetime.now().replace(tzinfo=None))
    bytes_sent: int = 0
    bytes_received: int = 0
    certificate_chain: list[CertificateInfo] = field(default_factory=list)
    dns_queries: list[str] = field(default_factory=list)
    suspicious: bool = False
    reason: str = ""


@dataclass
class TimelineEvent:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now().replace(tzinfo=None))
    category: str = ""
    title: str = ""
    description: str = ""
    source: str = ""
    severity: Severity = Severity.INFO
    metadata: dict[str, Any] = field(default_factory=dict)
    related_findings: list[str] = field(default_factory=list)


@dataclass
class YaraMatch:
    rule_name: str = ""
    namespace: str = ""
    meta: dict[str, str] = field(default_factory=dict)
    strings: list[tuple[str, int, str]] = field(default_factory=list)
    description: str = ""
    author: str = ""
    severity: Severity = Severity.INFO
    tags: list[str] = field(default_factory=list)
    file_path: str = ""
    offset: int = 0
    matched_data: bytes = b""


@dataclass
class PluginMetadata:
    name: str = ""
    version: str = ""
    author: str = ""
    description: str = ""
    commands: list[str] = field(default_factory=list)
    scanners: list[str] = field(default_factory=list)
    rules: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class AppInfo:
    package_name: str = ""
    version_name: str = ""
    version_code: int = 0
    target_sdk: int = 0
    min_sdk: int = 0
    app_category: AppCategory = AppCategory.UNKNOWN
    is_debuggable: bool = False
    is_backup_allowed: bool = True
    has_native_code: bool = False
    has_native_libs: bool = False
    has_dynamic_code: bool = False
    permissions: list[PermissionInfo] = field(default_factory=list)
    components: list[ComponentInfo] = field(default_factory=list)
    native_libraries: list[NativeLibrary] = field(default_factory=list)
    certificate: CertificateInfo | None = None
    install_time: datetime | None = None
    update_time: datetime | None = None
    last_used: datetime | None = None
    size_bytes: int = 0
    data_dir: str = ""
    apk_path: str = ""
    apk_hash: Hash | None = None
    trackers: list[str] = field(default_factory=list)
    embedded_urls: list[str] = field(default_factory=list)
    embedded_ips: list[str] = field(default_factory=list)
    shared_libraries: list[str] = field(default_factory=list)
    features: list[str] = field(default_factory=list)

    @property
    def exported_components(self) -> list[ComponentInfo]:
        return [c for c in self.components if c.exported]

    @property
    def dangerous_permissions(self) -> list[PermissionInfo]:
        return [p for p in self.permissions if p.is_risky]

    @property
    def open_components(self) -> list[ComponentInfo]:
        return [c for c in self.components if c.is_open]

    @property
    def total_permissions(self) -> int:
        return len(self.permissions)

    @property
    def risk_rating(self) -> Severity:
        score = 0
        if self.is_debuggable:
            score += 2
        if self.dangerous_permissions:
            score += len(self.dangerous_permissions)
        if self.open_components:
            score += len(self.open_components) * 2
        if self.has_dynamic_code:
            score += 3
        if self.has_native_code:
            score += 1
        if score >= 10:
            return Severity.CRITICAL
        if score >= 7:
            return Severity.HIGH
        if score >= 4:
            return Severity.MEDIUM
        if score >= 1:
            return Severity.LOW
        return Severity.INFO

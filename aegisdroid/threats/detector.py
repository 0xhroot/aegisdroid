"""Threat detection and correlation engine."""

from __future__ import annotations

import logging

from aegisdroid.core.domain import (
    AppInfo,
    ComponentType,
    Evidence,
    EvidenceType,
    Finding,
    PermissionInfo,
    ScanResult,
    Severity,
    ThreatCategory,
)

logger = logging.getLogger(__name__)


class ThreatDetector:
    """Correlation-based threat detection engine."""

    async def analyze(
        self, scan_result: ScanResult, app_info: AppInfo | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []

        if app_info:
            findings.extend(self._check_permissions(app_info))
            findings.extend(self._check_exported_components(app_info))
            findings.extend(self._check_dynamic_code(app_info))
            findings.extend(self._check_certificate(app_info))
            findings.extend(self._check_debuggable(app_info))
            findings.extend(self._check_trackers(app_info))
            findings.extend(self._check_embedded_urls(app_info))
            findings.extend(self._check_native_code(app_info))

        findings.extend(self._correlate_behavior(findings, app_info))

        return findings

    def _check_permissions(self, app: AppInfo) -> list[Finding]:
        findings = []
        dangerous = app.dangerous_permissions

        if len(dangerous) >= 5:
            [p.name for p in dangerous]
            findings.append(
                Finding(
                    category=ThreatCategory.SUSPICIOUS_PERMISSION,
                    severity=Severity.MEDIUM,
                    title=f"Excessive dangerous permissions ({len(dangerous)})",
                    description=(
                        f"App '{app.package_name}' requests {len(dangerous)} dangerous "
                        f"permissions. This may indicate overly broad data access."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.PERMISSION,
                            source="permission_analysis",
                            description=f"Dangerous permission: {p.name}",
                            confidence=0.8,
                        )
                        for p in dangerous
                    ],
                    confidence=min(0.9, 0.3 + len(dangerous) * 0.06),
                    mitigation="Review if all requested permissions are necessary for app functionality.",
                )
            )

        if PermissionInfo(name="android.permission.ACCESSIBILITY_SERVICE") in list(app.permissions):
            pass

        accessibility = [p for p in app.permissions if "accessibility" in p.name.lower()]
        if accessibility:
            findings.append(
                Finding(
                    category=ThreatCategory.ACCESSIBILITY_ABUSE,
                    severity=Severity.HIGH,
                    title="Accessibility service permission requested",
                    description=(
                        f"App '{app.package_name}' requests accessibility service "
                        f"access. This grants the ability to read screen content "
                        f"and perform actions on behalf of the user."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.PERMISSION,
                            source="permission_analysis",
                            description=f"Accessibility permission: {p.name}",
                            confidence=0.9,
                        )
                        for p in accessibility
                    ],
                    confidence=0.75,
                    mitigation="Accessibility access is commonly abused by malware and stalkerware.",
                )
            )

        overlay = [
            p
            for p in app.permissions
            if "system_alert_window" in p.name.lower() or "overlay" in p.name.lower()
        ]
        if overlay:
            findings.append(
                Finding(
                    category=ThreatCategory.OVERLAY_ATTACK,
                    severity=Severity.MEDIUM,
                    title="Overlay permission requested",
                    description=(
                        f"App '{app.package_name}' requests the ability to draw "
                        f"over other apps. This can be used for overlay attacks."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.PERMISSION,
                            source="permission_analysis",
                            description=f"Overlay permission: {p.name}",
                            confidence=0.85,
                        )
                        for p in overlay
                    ],
                    confidence=0.6,
                    mitigation="Overlay permissions can be used for phishing via overlay attacks.",
                )
            )

        sms_perms = [p for p in app.permissions if "sms" in p.name.lower()]
        if sms_perms:
            findings.append(
                Finding(
                    category=ThreatCategory.SMS_FRAUD,
                    severity=Severity.MEDIUM,
                    title="SMS permissions requested",
                    description=f"App '{app.package_name}' requests SMS-related permissions.",
                    evidence=[
                        Evidence(
                            type=EvidenceType.PERMISSION,
                            source="permission_analysis",
                            description=f"SMS permission: {p.name}",
                            confidence=0.8,
                        )
                        for p in sms_perms
                    ],
                    confidence=0.5,
                    mitigation="SMS permissions can be used for premium SMS fraud.",
                )
            )

        return findings

    def _check_exported_components(self, app: AppInfo) -> list[Finding]:
        findings = []
        open_components = app.open_components

        if open_components:
            exported_services = [
                c for c in open_components if c.component_type == ComponentType.SERVICE
            ]
            exported_receivers = [
                c for c in open_components if c.component_type == ComponentType.RECEIVER
            ]
            exported_providers = [
                c for c in open_components if c.component_type == ComponentType.PROVIDER
            ]

            if exported_services:
                findings.append(
                    Finding(
                        category=ThreatCategory.SUSPICIOUS_PERMISSION,
                        severity=Severity.MEDIUM,
                        title=f"Exported unprotected services ({len(exported_services)})",
                        description=(
                            f"App '{app.package_name}' has {len(exported_services)} "
                            f"exported services without permission protection."
                        ),
                        evidence=[
                            Evidence(
                                type=EvidenceType.STATIC_ANALYSIS,
                                source="component_analysis",
                                description=f"Exported service: {s.name}",
                                confidence=0.85,
                            )
                            for s in exported_services
                        ],
                        confidence=0.65,
                        mitigation="Exported services without protection can be accessed by any app.",
                    )
                )

            if exported_receivers:
                findings.append(
                    Finding(
                        category=ThreatCategory.SUSPICIOUS_PERMISSION,
                        severity=Severity.HIGH,
                        title=f"Exported unprotected broadcast receivers ({len(exported_receivers)})",
                        description=(
                            f"App '{app.package_name}' has {len(exported_receivers)} "
                            f"exported receivers that can be triggered by any app."
                        ),
                        evidence=[
                            Evidence(
                                type=EvidenceType.STATIC_ANALYSIS,
                                source="component_analysis",
                                description=f"Exported receiver: {r.name}",
                                confidence=0.9,
                            )
                            for r in exported_receivers
                        ],
                        confidence=0.7,
                        mitigation="Exported receivers can be triggered externally for code execution.",
                    )
                )

            if exported_providers:
                findings.append(
                    Finding(
                        category=ThreatCategory.DATA_EXFIL,
                        severity=Severity.HIGH,
                        title=f"Exported content providers ({len(exported_providers)})",
                        description=(
                            f"App '{app.package_name}' has {len(exported_providers)} "
                            f"exported content providers that may expose data."
                        ),
                        evidence=[
                            Evidence(
                                type=EvidenceType.STATIC_ANALYSIS,
                                source="component_analysis",
                                description=f"Exported provider: {p.name}",
                                confidence=0.9,
                            )
                            for p in exported_providers
                        ],
                        confidence=0.75,
                        mitigation="Exported providers can leak data or be exploited for SQL injection.",
                    )
                )

        return findings

    def _check_dynamic_code(self, app: AppInfo) -> list[Finding]:
        findings = []
        if app.has_dynamic_code:
            findings.append(
                Finding(
                    category=ThreatCategory.DYNAMIC_CODE,
                    severity=Severity.HIGH,
                    title="Dynamic code loading detected",
                    description=(
                        f"App '{app.package_name}' uses dynamic code loading. "
                        f"This technique is commonly used by malware to evade "
                        f"detection and load payloads at runtime."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.STATIC_ANALYSIS,
                            source="dex_analysis",
                            description="Dynamic class loading or reflection detected in DEX",
                            confidence=0.85,
                        )
                    ],
                    confidence=0.7,
                    mitigation="Dynamic code loading is a common evasion technique.",
                )
            )
        return findings

    def _check_certificate(self, app: AppInfo) -> list[Finding]:
        findings = []
        cert = app.certificate
        if not cert:
            findings.append(
                Finding(
                    category=ThreatCategory.CERTIFICATE_ANOMALY,
                    severity=Severity.LOW,
                    title="No certificate information available",
                    description=f"Could not extract certificate for '{app.package_name}'.",
                    evidence=[],
                    confidence=0.4,
                )
            )
            return findings

        if cert.is_debug:
            findings.append(
                Finding(
                    category=ThreatCategory.CERTIFICATE_ANOMALY,
                    severity=Severity.MEDIUM,
                    title="Debug signing certificate",
                    description=(
                        f"App '{app.package_name}' is signed with a debug certificate. "
                        f"This indicates it was not built for production release."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.CERTIFICATE,
                            source="certificate_analysis",
                            description="Debug certificate detected",
                            confidence=0.95,
                        )
                    ],
                    confidence=0.9,
                    mitigation="Debug-signed apps should not be deployed in production.",
                )
            )

        if cert.is_self_signed:
            findings.append(
                Finding(
                    category=ThreatCategory.CERTIFICATE_ANOMALY,
                    severity=Severity.MEDIUM,
                    title="Self-signed certificate",
                    description=(
                        f"App '{app.package_name}' uses a self-signed certificate. "
                        f"This reduces accountability and trust."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.CERTIFICATE,
                            source="certificate_analysis",
                            description="Self-signed certificate",
                            confidence=0.9,
                        )
                    ],
                    confidence=0.7,
                    mitigation="Self-signed certificates provide no third-party verification.",
                )
            )

        if cert.is_weak_key:
            findings.append(
                Finding(
                    category=ThreatCategory.CERTIFICATE_ANOMALY,
                    severity=Severity.MEDIUM,
                    title="Weak signing key",
                    description=(
                        f"App '{app.package_name}' uses a signing key with "
                        f"{cert.key_size}-bit key. Minimum recommended is 2048-bit."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.CERTIFICATE,
                            source="certificate_analysis",
                            description=f"Key size: {cert.key_size} bits",
                            confidence=0.95,
                        )
                    ],
                    confidence=0.9,
                    mitigation="Upgrade to at least 2048-bit RSA or 256-bit EC key.",
                )
            )

        if cert.is_expired:
            findings.append(
                Finding(
                    category=ThreatCategory.CERTIFICATE_ANOMALY,
                    severity=Severity.MEDIUM,
                    title="Expired signing certificate",
                    description=f"App '{app.package_name}' has an expired signing certificate.",
                    evidence=[
                        Evidence(
                            type=EvidenceType.CERTIFICATE,
                            source="certificate_analysis",
                            description=f"Expired: {cert.not_after}",
                            confidence=1.0,
                        )
                    ],
                    confidence=0.95,
                    mitigation="Certificate should be renewed.",
                )
            )

        return findings

    def _check_debuggable(self, app: AppInfo) -> list[Finding]:
        findings = []
        if app.is_debuggable:
            findings.append(
                Finding(
                    category=ThreatCategory.PRIVILEGE_ESCALATION,
                    severity=Severity.MEDIUM,
                    title="Application is debuggable",
                    description=(
                        f"App '{app.package_name}' has android:debuggable=true. "
                        f"This allows attaching a debugger and inspecting runtime state."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.STATIC_ANALYSIS,
                            source="manifest_analysis",
                            description="android:debuggable=true in manifest",
                            confidence=0.95,
                        )
                    ],
                    confidence=0.9,
                    mitigation="Debuggable apps can be reverse-engineered at runtime.",
                )
            )
        return findings

    def _check_trackers(self, app: AppInfo) -> list[Finding]:
        findings = []
        if app.trackers:
            findings.append(
                Finding(
                    category=ThreatCategory.BEHAVIORAL_ANOMALY,
                    severity=Severity.LOW,
                    title=f"Tracking SDKs detected ({len(app.trackers)})",
                    description=(
                        f"App '{app.package_name}' includes {len(app.trackers)} "
                        f"tracking SDK(s): {', '.join(app.trackers)}"
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.STATIC_ANALYSIS,
                            source="tracker_detection",
                            description=f"Tracker: {t}",
                            confidence=0.8,
                        )
                        for t in app.trackers
                    ],
                    confidence=0.85,
                    mitigation="Review data collection policies of embedded trackers.",
                )
            )
        return findings

    def _check_embedded_urls(self, app: AppInfo) -> list[Finding]:
        findings = []
        if app.embedded_urls:
            findings.append(
                Finding(
                    category=ThreatCategory.NETWORK_ANOMALY,
                    severity=Severity.MEDIUM,
                    title=f"Suspicious embedded URLs ({len(app.embedded_urls)})",
                    description=(
                        f"App '{app.package_name}' contains {len(app.embedded_urls)} "
                        f"suspicious URLs that may indicate C2 communication."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.STATIC_ANALYSIS,
                            source="string_analysis",
                            description=f"Suspicious URL: {u}",
                            confidence=0.7,
                        )
                        for u in app.embedded_urls[:10]
                    ],
                    confidence=0.6,
                    mitigation="Investigate embedded URLs for potential C2 or data exfiltration.",
                )
            )

        if app.embedded_ips:
            findings.append(
                Finding(
                    category=ThreatCategory.NETWORK_ANOMALY,
                    severity=Severity.MEDIUM,
                    title=f"Embedded IP addresses ({len(app.embedded_ips)})",
                    description=(
                        f"App '{app.package_name}' contains {len(app.embedded_ips)} "
                        f"hardcoded IP addresses."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.STATIC_ANALYSIS,
                            source="string_analysis",
                            description=f"Embedded IP: {ip}",
                            confidence=0.6,
                        )
                        for ip in app.embedded_ips[:10]
                    ],
                    confidence=0.5,
                    mitigation="Hardcoded IPs may indicate C2 infrastructure.",
                )
            )
        return findings

    def _check_native_code(self, app: AppInfo) -> list[Finding]:
        findings = []
        if app.has_native_code:
            findings.append(
                Finding(
                    category=ThreatCategory.BEHAVIORAL_ANOMALY,
                    severity=Severity.LOW,
                    title=f"Native libraries detected ({len(app.native_libraries)})",
                    description=(
                        f"App '{app.package_name}' includes {len(app.native_libraries)} "
                        f"native libraries. These can be harder to analyze."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.STATIC_ANALYSIS,
                            source="native_analysis",
                            description=f"Native lib: {lib.name}",
                            confidence=0.8,
                        )
                        for lib in app.native_libraries
                    ],
                    confidence=0.5,
                    mitigation="Native code requires additional reverse engineering effort.",
                )
            )
        return findings

    def _correlate_behavior(self, findings: list[Finding], app: AppInfo | None) -> list[Finding]:
        correlated: list[Finding] = []
        if not app:
            return correlated

        categories = {f.category for f in findings}
        evidence_items = []
        evidence_text = []

        has_accessibility = ThreatCategory.ACCESSIBILITY_ABUSE in categories
        has_overlay = ThreatCategory.OVERLAY_ATTACK in categories
        has_dynamic = ThreatCategory.DYNAMIC_CODE in categories
        has_network = ThreatCategory.NETWORK_ANOMALY in categories

        if has_accessibility and has_overlay:
            evidence_items.append(
                Evidence(
                    type=EvidenceType.BEHAVIORAL,
                    source="correlation_engine",
                    description="Combination of accessibility + overlay permissions",
                    confidence=0.95,
                )
            )
            evidence_text.append("accessibility + overlay combination")
            correlated.append(
                Finding(
                    category=ThreatCategory.OVERLAY_ATTACK,
                    severity=Severity.HIGH,
                    title="Overlay attack pattern detected",
                    description=(
                        "App combines accessibility and overlay permissions, "
                        "a pattern commonly seen in overlay phishing attacks."
                    ),
                    evidence=evidence_items[-1:],
                    confidence=0.8,
                    mitigation="This pattern is commonly associated with credential theft.",
                )
            )

        if has_accessibility and has_dynamic:
            correlated.append(
                Finding(
                    category=ThreatCategory.BEHAVIORAL_ANOMALY,
                    severity=Severity.HIGH,
                    title="Accessibility abuse with dynamic code loading",
                    description=(
                        "App uses both accessibility services and dynamic code loading. "
                        "This combination is a strong indicator of malicious behavior."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.BEHAVIORAL,
                            source="correlation_engine",
                            description="accessibility + dynamic code loading",
                            confidence=0.9,
                        )
                    ],
                    confidence=0.85,
                    mitigation="This combination is frequently found in banking trojans and spyware.",
                )
            )

        if has_network and has_dynamic:
            correlated.append(
                Finding(
                    category=ThreatCategory.DATA_EXFIL,
                    severity=Severity.HIGH,
                    title="Potential data exfiltration vector",
                    description=(
                        "App has network indicators and dynamic code loading capability. "
                        "This combination can be used for remote payload delivery and "
                        "data exfiltration."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.BEHAVIORAL,
                            source="correlation_engine",
                            description="network + dynamic code loading",
                            confidence=0.85,
                        )
                    ],
                    confidence=0.7,
                    mitigation="Monitor network traffic for suspicious data transfers.",
                )
            )

        dangerous_count = len(app.dangerous_permissions)
        exported_count = len(app.exported_components)

        if dangerous_count >= 8 and exported_count >= 3:
            correlated.append(
                Finding(
                    category=ThreatCategory.BEHAVIORAL_ANOMALY,
                    severity=Severity.HIGH,
                    title="Overprivileged app with many exported components",
                    description=(
                        f"App has {dangerous_count} dangerous permissions and "
                        f"{exported_count} exported components. This broad attack "
                        f"surface is unusual for legitimate apps."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.BEHAVIORAL,
                            source="correlation_engine",
                            description=f"{dangerous_count} dangerous perms + {exported_count} exported",
                            confidence=0.8,
                        )
                    ],
                    confidence=0.7,
                    mitigation="Excessive permissions and exported components increase risk.",
                )
            )

        return correlated

    async def calculate_threat_score(self, findings: list[Finding]) -> float:
        if not findings:
            return 0.0
        total = sum(f.risk_score for f in findings)
        return min(1.0, total / max(len(findings), 1))

    async def correlate(self, findings: list[Finding]) -> list[Finding]:
        return findings

    async def explain(self, finding: Finding) -> str:
        return finding.explain()

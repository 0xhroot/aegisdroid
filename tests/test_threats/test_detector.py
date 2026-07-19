"""Tests for the threat detection engine."""

import pytest

from aegisdroid.core.domain import (
    AppInfo,
    CertificateInfo,
    ComponentInfo,
    ComponentType,
    Finding,
    PermissionInfo,
    ScanResult,
    Severity,
    ThreatCategory,
)
from aegisdroid.threats.detector import ThreatDetector


@pytest.fixture
def detector():
    return ThreatDetector()


class TestPermissionAnalysis:
    @pytest.mark.asyncio
    async def test_excessive_permissions(self, detector):
        app = AppInfo(
            package_name="com.test.app",
            permissions=[
                PermissionInfo(name="android.permission.CAMERA"),
                PermissionInfo(name="android.permission.READ_SMS"),
                PermissionInfo(name="android.permission.RECORD_AUDIO"),
                PermissionInfo(name="android.permission.ACCESS_FINE_LOCATION"),
                PermissionInfo(name="android.permission.READ_CONTACTS"),
                PermissionInfo(name="android.permission.INTERNET"),
            ],
        )
        scan = ScanResult()
        findings = await detector.analyze(scan, app)
        perm_findings = [f for f in findings if f.category == ThreatCategory.SUSPICIOUS_PERMISSION]
        assert len(perm_findings) > 0

    @pytest.mark.asyncio
    async def test_accessibility_permission(self, detector):
        app = AppInfo(
            package_name="com.test.app",
            permissions=[
                PermissionInfo(name="android.permission.BIND_ACCESSIBILITY_SERVICE"),
            ],
        )
        scan = ScanResult()
        findings = await detector.analyze(scan, app)
        access_findings = [f for f in findings if f.category == ThreatCategory.ACCESSIBILITY_ABUSE]
        assert len(access_findings) == 1
        assert access_findings[0].severity == Severity.HIGH


class TestComponentAnalysis:
    @pytest.mark.asyncio
    async def test_exported_services(self, detector):
        app = AppInfo(
            package_name="com.test.app",
            components=[
                ComponentInfo(
                    name="com.test.ExportSvc",
                    component_type=ComponentType.SERVICE,
                    exported=True,
                    permission="",
                ),
            ],
        )
        scan = ScanResult()
        findings = await detector.analyze(scan, app)
        comp_findings = [f for f in findings if "Exported" in f.title]
        assert len(comp_findings) > 0

    @pytest.mark.asyncio
    async def test_exported_providers(self, detector):
        app = AppInfo(
            package_name="com.test.app",
            components=[
                ComponentInfo(
                    name="com.test.DataProvider",
                    component_type=ComponentType.PROVIDER,
                    exported=True,
                    permission="",
                ),
            ],
        )
        scan = ScanResult()
        findings = await detector.analyze(scan, app)
        provider_findings = [f for f in findings if "provider" in f.title.lower()]
        assert len(provider_findings) > 0


class TestDynamicCodeDetection:
    @pytest.mark.asyncio
    async def test_dynamic_code(self, detector):
        app = AppInfo(
            package_name="com.test.app",
            has_dynamic_code=True,
        )
        scan = ScanResult()
        findings = await detector.analyze(scan, app)
        dynamic_findings = [f for f in findings if f.category == ThreatCategory.DYNAMIC_CODE]
        assert len(dynamic_findings) == 1
        assert dynamic_findings[0].severity == Severity.HIGH


class TestCertificateAnalysis:
    @pytest.mark.asyncio
    async def test_debug_certificate(self, detector):
        app = AppInfo(
            package_name="com.test.app",
            certificate=CertificateInfo(is_debug=True),
        )
        scan = ScanResult()
        findings = await detector.analyze(scan, app)
        cert_findings = [f for f in findings if "debug" in f.title.lower()]
        assert len(cert_findings) > 0

    @pytest.mark.asyncio
    async def test_self_signed(self, detector):
        app = AppInfo(
            package_name="com.test.app",
            certificate=CertificateInfo(is_self_signed=True),
        )
        scan = ScanResult()
        findings = await detector.analyze(scan, app)
        cert_findings = [f for f in findings if "self-signed" in f.title.lower()]
        assert len(cert_findings) > 0


class TestCorrelationEngine:
    @pytest.mark.asyncio
    async def test_overlay_attack_pattern(self, detector):
        app = AppInfo(
            package_name="com.test.app",
            permissions=[
                PermissionInfo(name="android.permission.BIND_ACCESSIBILITY_SERVICE"),
                PermissionInfo(name="android.permission.SYSTEM_ALERT_WINDOW"),
                PermissionInfo(name="android.permission.INTERNET"),
            ],
            components=[
                ComponentInfo(
                    name="com.test.ExportSvc",
                    component_type=ComponentType.SERVICE,
                    exported=True,
                    permission="",
                ),
            ],
        )
        scan = ScanResult()
        findings = await detector.analyze(scan, app)
        overlay_findings = [f for f in findings if "overlay attack" in f.title.lower()]
        assert len(overlay_findings) > 0
        assert overlay_findings[0].severity == Severity.HIGH


class TestThreatScore:
    @pytest.mark.asyncio
    async def test_empty_findings(self, detector):
        score = await detector.calculate_threat_score([])
        assert score == 0.0

    @pytest.mark.asyncio
    async def test_calculate_score(self, detector):
        findings = [
            Finding(severity=Severity.CRITICAL, confidence=1.0),
            Finding(severity=Severity.HIGH, confidence=0.8),
        ]
        score = await detector.calculate_threat_score(findings)
        assert score > 0.0
        assert score <= 1.0

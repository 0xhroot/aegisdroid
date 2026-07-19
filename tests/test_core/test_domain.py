"""Tests for AegisDroid core domain models."""

from datetime import datetime

import pytest

from aegisdroid.core.domain import (
    AppInfo,
    CertificateInfo,
    ComponentInfo,
    ComponentType,
    Domain,
    Evidence,
    EvidenceType,
    Finding,
    Hash,
    PermissionInfo,
    ScanResult,
    Severity,
    ThreatCategory,
    Version,
)


class TestHash:
    def test_from_bytes(self):
        h = Hash.from_bytes(b"test data")
        assert len(h.sha256) == 64
        assert len(h.md5) == 32
        assert len(h.sha1) == 40

    def test_str_returns_sha256(self):
        h = Hash(sha256="abc123", md5="def456")
        assert str(h) == "abc123"


class TestVersion:
    def test_parse(self):
        v = Version.parse("1.2.3")
        assert v.major == 1
        assert v.minor == 2
        assert v.patch == 3

    def test_str(self):
        v = Version(1, 2, 3)
        assert str(v) == "1.2.3"


class TestDomain:
    def test_is_suspicious(self):
        d = Domain(name="malicious.tk", reputation=0.1)
        assert d.is_suspicious

    def test_not_suspicious(self):
        d = Domain(name="google.com", reputation=0.9)
        assert not d.is_suspicious


class TestEvidence:
    def test_summary(self):
        e = Evidence(
            type=EvidenceType.STATIC_ANALYSIS,
            source="test",
            description="Found something",
        )
        assert "static_analysis" in e.summary
        assert "Found something" in e.summary


class TestFinding:
    def test_risk_score_critical(self):
        f = Finding(severity=Severity.CRITICAL, confidence=0.9)
        assert f.risk_score == pytest.approx(0.9)

    def test_risk_score_medium(self):
        f = Finding(severity=Severity.MEDIUM, confidence=0.8)
        assert f.risk_score == pytest.approx(0.4)

    def test_explain(self):
        f = Finding(
            category=ThreatCategory.ROOT,
            severity=Severity.HIGH,
            title="Root detected",
            description="Device is rooted",
            confidence=0.85,
        )
        explanation = f.explain()
        assert "root" in explanation
        assert "HIGH" in explanation
        assert "85%" in explanation


class TestScanResult:
    def test_empty_scan(self):
        r = ScanResult()
        assert r.threat_confidence_score == 0.0

    def test_threat_score(self):
        r = ScanResult(
            findings=[
                Finding(severity=Severity.HIGH, confidence=0.8),
                Finding(severity=Severity.MEDIUM, confidence=0.6),
            ]
        )
        assert r.threat_confidence_score > 0


class TestAppInfo:
    def test_risk_rating_debuggable(self):
        app = AppInfo(is_debuggable=True)
        assert app.risk_rating in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)

    def test_exported_components(self):
        app = AppInfo(
            components=[
                ComponentInfo(
                    name="ExportedAct", exported=True, component_type=ComponentType.ACTIVITY
                ),
                ComponentInfo(
                    name="PrivateAct", exported=False, component_type=ComponentType.ACTIVITY
                ),
            ]
        )
        assert len(app.exported_components) == 1

    def test_open_components(self):
        app = AppInfo(
            components=[
                ComponentInfo(
                    name="Open", exported=True, permission="", component_type=ComponentType.SERVICE
                ),
                ComponentInfo(
                    name="Protected",
                    exported=True,
                    permission="android.permission.BIND",
                    component_type=ComponentType.SERVICE,
                    is_protected=True,
                ),
            ]
        )
        assert len(app.open_components) == 1


class TestPermissionInfo:
    def test_risky_permission(self):
        p = PermissionInfo(name="android.permission.CAMERA")
        assert p.is_risky

    def test_normal_permission(self):
        p = PermissionInfo(name="android.permission.INTERNET")
        assert not p.is_risky


class TestCertificateInfo:
    def test_expired(self):
        c = CertificateInfo(not_after=datetime(2020, 1, 1))
        assert c.is_expired

    def test_weak_key(self):
        c = CertificateInfo(key_size=1024)
        assert c.is_weak_key

    def test_strong_key(self):
        c = CertificateInfo(key_size=2048)
        assert not c.is_weak_key

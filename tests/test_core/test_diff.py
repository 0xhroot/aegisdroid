"""Tests for the diff engine."""

import pytest

from aegisdroid.core.domain import Finding, ScanResult, Severity
from aegisdroid.diff.engine import DiffEngine


@pytest.fixture
def engine():
    return DiffEngine()


class TestDiffEngine:
    def test_identical_scans(self, engine):
        old = ScanResult(
            findings=[
                Finding(title="F1", severity=Severity.HIGH, confidence=0.8),
            ]
        )
        new = ScanResult(
            findings=[
                Finding(title="F1", severity=Severity.HIGH, confidence=0.8),
            ]
        )
        result = engine.diff(old, new)
        assert len(result.added_findings) == 0
        assert len(result.removed_findings) == 0
        assert len(result.unchanged_findings) == 1

    def test_added_finding(self, engine):
        old = ScanResult(findings=[])
        new = ScanResult(
            findings=[
                Finding(title="New Finding", severity=Severity.CRITICAL, confidence=0.9),
            ]
        )
        result = engine.diff(old, new)
        assert len(result.added_findings) == 1
        assert result.added_findings[0]["title"] == "New Finding"

    def test_removed_finding(self, engine):
        old = ScanResult(
            findings=[
                Finding(title="Old Finding", severity=Severity.HIGH, confidence=0.8),
            ]
        )
        new = ScanResult(findings=[])
        result = engine.diff(old, new)
        assert len(result.removed_findings) == 1

    def test_modified_finding(self, engine):
        old = ScanResult(
            findings=[
                Finding(title="F1", severity=Severity.MEDIUM, confidence=0.5),
            ]
        )
        new = ScanResult(
            findings=[
                Finding(title="F1", severity=Severity.HIGH, confidence=0.9),
            ]
        )
        result = engine.diff(old, new)
        assert len(result.modified_findings) == 1
        assert result.modified_findings[0]["old_severity"] == "medium"
        assert result.modified_findings[0]["new_severity"] == "high"

    def test_format_diff(self, engine):
        old = ScanResult(
            findings=[
                Finding(title="Removed", severity=Severity.LOW, confidence=0.3),
            ]
        )
        new = ScanResult(
            findings=[
                Finding(title="Added", severity=Severity.HIGH, confidence=0.8),
            ]
        )
        result = engine.diff(old, new)
        formatted = engine.format_diff(result)
        assert "Differential Analysis" in formatted
        assert "Added" in formatted
        assert "Removed" in formatted

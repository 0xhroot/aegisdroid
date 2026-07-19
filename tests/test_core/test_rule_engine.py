"""Tests for the rule engine."""

import pytest

from aegisdroid.core.domain import (
    Finding,
    ScanResult,
    Severity,
)
from aegisdroid.rules.engine import RuleEngine


@pytest.fixture
def engine():
    return RuleEngine()


class TestRuleEngine:
    @pytest.mark.asyncio
    async def test_evaluate_matching_rule(self, engine):
        rule = {
            "name": "test_rule",
            "severity": "high",
            "title": "Test Finding",
            "description": "Test description",
            "category": "custom",
            "when": {
                "min_findings": 2,
            },
            "confidence": 0.8,
        }
        scan = ScanResult(
            findings=[
                Finding(severity=Severity.MEDIUM, title="F1"),
                Finding(severity=Severity.LOW, title="F2"),
            ]
        )
        findings = await engine.evaluate(scan, [rule])
        assert len(findings) == 1
        assert findings[0].title == "Test Finding"

    @pytest.mark.asyncio
    async def test_evaluate_non_matching_rule(self, engine):
        rule = {
            "name": "test_rule",
            "severity": "high",
            "title": "Test Finding",
            "description": "Test",
            "category": "custom",
            "when": {
                "min_findings": 5,
            },
            "confidence": 0.8,
        }
        scan = ScanResult(findings=[Finding()])
        findings = await engine.evaluate(scan, [rule])
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_validate_rule(self, engine):
        valid = {"name": "test", "severity": "high", "when": {}, "title": "Test"}
        assert await engine.validate_rule(valid)

        invalid = {"name": "test"}
        assert not await engine.validate_rule(invalid)

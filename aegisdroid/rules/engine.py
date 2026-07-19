"""Custom YAML rule engine for threat detection."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from aegisdroid.core.domain import (
    Evidence,
    EvidenceType,
    Finding,
    ScanResult,
    Severity,
    ThreatCategory,
)

logger = logging.getLogger(__name__)


class RuleEngine:
    """Evaluate custom YAML-based detection rules."""

    SEVERITY_MAP = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }

    async def load_rules(self, rules_path: str) -> list[dict[str, Any]]:
        path = Path(rules_path)
        if not path.exists():
            logger.warning("Rules path does not exist: %s", rules_path)
            return []

        rules: list[dict[str, Any]] = []
        for rule_file in path.rglob("*.yaml"):
            try:
                with open(rule_file) as f:
                    data = yaml.safe_load(f)
                if isinstance(data, list):
                    for rule in data:
                        if isinstance(rule, dict):
                            rule["_file"] = str(rule_file)
                            rules.append(rule)
                elif isinstance(data, dict) and "rules" in data:
                    for rule in data["rules"]:
                        rule["_file"] = str(rule_file)
                        rules.append(rule)
                elif isinstance(data, dict) and "name" in data:
                    data["_file"] = str(rule_file)
                    rules.append(data)
            except Exception as e:
                logger.exception("Error loading rule %s: %s", rule_file, e)

        for rule_file in path.rglob("*.yml"):
            try:
                with open(rule_file) as f:
                    data = yaml.safe_load(f)
                if isinstance(data, list):
                    for rule in data:
                        if isinstance(rule, dict):
                            rule["_file"] = str(rule_file)
                            rules.append(rule)
                elif isinstance(data, dict) and "rules" in data:
                    for rule in data["rules"]:
                        rule["_file"] = str(rule_file)
                        rules.append(rule)
            except Exception as e:
                logger.exception("Error loading rule %s: %s", rule_file, e)

        return rules

    async def evaluate(self, scan_result: ScanResult, rules: list[dict[str, Any]]) -> list[Finding]:
        findings: list[Finding] = []
        for rule in rules:
            finding = self._evaluate_rule(rule, scan_result)
            if finding:
                findings.append(finding)
        return findings

    def _evaluate_rule(self, rule: dict[str, Any], scan_result: ScanResult) -> Finding | None:
        conditions = rule.get("when", {})
        if not conditions:
            return None

        all_met = True
        evidence_list: list[Evidence] = []

        for condition_type, expected in conditions.items():
            met = self._check_condition(condition_type, expected, scan_result, evidence_list)
            if not met:
                all_met = False
                break

        if not all_met:
            return None

        severity_str = rule.get("severity", "medium")
        severity = self.SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

        return Finding(
            category=ThreatCategory(rule.get("category", "custom")),
            severity=severity,
            title=rule.get("title", "Custom rule triggered"),
            description=rule.get("description", ""),
            evidence=evidence_list,
            confidence=float(rule.get("confidence", 0.7)),
            mitigation=rule.get("mitigation", ""),
            references=rule.get("references", []),
        )

    def _check_condition(
        self,
        condition_type: str,
        expected: Any,
        scan_result: ScanResult,
        evidence_list: list[Evidence],
    ) -> bool:
        if condition_type == "has_finding_category":
            if isinstance(expected, str):
                for f in scan_result.findings:
                    if f.category.value == expected:
                        evidence_list.append(
                            Evidence(
                                type=EvidenceType.BEHAVIORAL,
                                source="rule_engine",
                                description=f"Finding category match: {expected}",
                                confidence=0.8,
                            )
                        )
                        return True
            elif isinstance(expected, list):
                for cat in expected:
                    found = any(f.category.value == cat for f in scan_result.findings)
                    if not found:
                        return False
                evidence_list.append(
                    Evidence(
                        type=EvidenceType.BEHAVIORAL,
                        source="rule_engine",
                        description=f"All finding categories matched: {expected}",
                        confidence=0.8,
                    )
                )
                return True
            return False

        if condition_type == "has_finding_severity":
            severity = expected
            for f in scan_result.findings:
                if f.severity.value == severity:
                    evidence_list.append(
                        Evidence(
                            type=EvidenceType.BEHAVIORAL,
                            source="rule_engine",
                            description=f"Finding with severity {severity} present",
                            confidence=0.8,
                        )
                    )
                    return True
            return False

        if condition_type == "min_findings":
            return len(scan_result.findings) >= int(expected)

        if condition_type == "min_threat_score":
            return scan_result.threat_confidence_score >= float(expected)

        if condition_type == "has_permission":
            metadata = scan_result.metadata
            permissions = metadata.get("permissions", [])
            if isinstance(expected, str):
                return expected in permissions
            if isinstance(expected, list):
                return all(p in permissions for p in expected)
            return False

        if condition_type == "has_component":
            metadata = scan_result.metadata
            components = metadata.get("exported_components", [])
            if isinstance(expected, str):
                return any(expected in c for c in components)
            return False

        if condition_type == "metadata_equals":
            if isinstance(expected, dict):
                for key, val in expected.items():
                    if scan_result.metadata.get(key) != val:
                        return False
                evidence_list.append(
                    Evidence(
                        type=EvidenceType.BEHAVIORAL,
                        source="rule_engine",
                        description=f"Metadata match: {expected}",
                        confidence=0.8,
                    )
                )
                return True
            return False

        return False

    async def validate_rule(self, rule: dict[str, Any]) -> bool:
        required = ["name", "severity", "when", "title"]
        return all(k in rule for k in required)

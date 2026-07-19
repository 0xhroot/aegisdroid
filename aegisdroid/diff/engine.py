"""Differential analysis between scans."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegisdroid.core.domain import ScanResult

logger = logging.getLogger(__name__)


@dataclass
class DiffResult:
    added_findings: list[dict[str, Any]] = field(default_factory=list)
    removed_findings: list[dict[str, Any]] = field(default_factory=list)
    unchanged_findings: list[dict[str, Any]] = field(default_factory=list)
    modified_findings: list[dict[str, Any]] = field(default_factory=list)
    score_change: float = 0.0
    timestamp_old: str = ""
    timestamp_new: str = ""


class DiffEngine:
    """Compare two scan results and generate diffs."""

    def diff(self, old: ScanResult, new: ScanResult) -> DiffResult:
        result = DiffResult(
            score_change=new.threat_confidence_score - old.threat_confidence_score,
            timestamp_old=old.started_at.isoformat(),
            timestamp_new=new.started_at.isoformat(),
        )

        old_findings = {f.title: f for f in old.findings}
        new_findings = {f.title: f for f in new.findings}

        for title, finding in new_findings.items():
            if title not in old_findings:
                result.added_findings.append(
                    {
                        "title": finding.title,
                        "severity": finding.severity.value,
                        "category": finding.category.value,
                        "confidence": finding.confidence,
                    }
                )
            else:
                old_f = old_findings[title]
                if old_f.severity != finding.severity or old_f.confidence != finding.confidence:
                    result.modified_findings.append(
                        {
                            "title": finding.title,
                            "old_severity": old_f.severity.value,
                            "new_severity": finding.severity.value,
                            "old_confidence": old_f.confidence,
                            "new_confidence": finding.confidence,
                        }
                    )
                else:
                    result.unchanged_findings.append(
                        {
                            "title": finding.title,
                            "severity": finding.severity.value,
                        }
                    )

        for title, finding in old_findings.items():
            if title not in new_findings:
                result.removed_findings.append(
                    {
                        "title": finding.title,
                        "severity": finding.severity.value,
                        "category": finding.category.value,
                    }
                )

        return result

    def format_diff(self, diff: DiffResult) -> str:
        lines = [
            "# Differential Analysis",
            "",
            f"**Baseline:** {diff.timestamp_old}",
            f"**Current:** {diff.timestamp_new}",
            f"**Score Change:** {diff.score_change:+.0%}",
            "",
        ]

        if diff.added_findings:
            lines.append("## New Findings (+)")
            for f in diff.added_findings:
                lines.append(f"+ [{f['severity'].upper()}] {f['title']}")
            lines.append("")

        if diff.removed_findings:
            lines.append("## Removed Findings (-)")
            for f in diff.removed_findings:
                lines.append(f"- [{f['severity'].upper()}] {f['title']}")
            lines.append("")

        if diff.modified_findings:
            lines.append("## Modified Findings (~)")
            for f in diff.modified_findings:
                lines.append(
                    f"~ {f['title']}: "
                    f"{f['old_severity']} -> {f['new_severity']} "
                    f"({f['old_confidence']:.0%} -> {f['new_confidence']:.0%})"
                )
            lines.append("")

        if not (diff.added_findings or diff.removed_findings or diff.modified_findings):
            lines.append("No changes detected.")

        return "\n".join(lines)

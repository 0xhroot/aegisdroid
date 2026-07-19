"""Global fuzzy search engine."""

from __future__ import annotations

import logging
from typing import Any

from aegisdroid.core.domain import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)


class SearchEngine:
    """Fuzzy search across all data."""

    def __init__(self) -> None:
        self._scan_history: list[ScanResult] = []

    def index_scan(self, scan: ScanResult) -> None:
        self._scan_history.append(scan)

    def search(self, query: str, limit: int = 50) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        query_lower = query.lower()

        for scan in self._scan_history:
            for finding in scan.findings:
                score = self._score_finding(finding, query_lower)
                if score > 0:
                    results.append(
                        {
                            "type": "finding",
                            "score": score,
                            "data": finding,
                            "scan_id": scan.id,
                        }
                    )

            for event in scan.metadata.get("timeline_events", []):
                if query_lower in str(event).lower():
                    results.append(
                        {
                            "type": "timeline_event",
                            "score": 0.5,
                            "data": event,
                            "scan_id": scan.id,
                        }
                    )

        results.sort(key=lambda r: r["score"], reverse=True)
        return results[:limit]

    def _score_finding(self, finding: Finding, query: str) -> float:
        score = 0.0
        searchable = (
            f"{finding.title} {finding.description} {finding.category.value} "
            f"{finding.severity.value} {finding.mitigation}".lower()
        )

        if query in searchable:
            score = 1.0
        else:
            query_words = query.split()
            matches = sum(1 for word in query_words if word in searchable)
            score = matches / max(len(query_words), 1)

        if score > 0 and finding.severity in (Severity.CRITICAL, Severity.HIGH):
            score *= 1.2

        return min(score, 2.0)

    def search_apps(self, query: str) -> list[dict[str, Any]]:
        results = []
        for scan in self._scan_history:
            pkg = scan.package_name
            if query.lower() in pkg.lower():
                results.append(
                    {
                        "type": "package",
                        "package": pkg,
                        "scan_id": scan.id,
                        "threat_score": scan.threat_confidence_score,
                    }
                )
        return results

    def search_permissions(self, query: str) -> list[dict[str, Any]]:
        results = []
        for scan in self._scan_history:
            perms = scan.metadata.get("permissions", [])
            for perm in perms:
                if query.lower() in perm.lower():
                    results.append(
                        {
                            "type": "permission",
                            "permission": perm,
                            "package": scan.package_name,
                            "scan_id": scan.id,
                        }
                    )
        return results

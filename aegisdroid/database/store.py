"""SQLite database adapter using SQLAlchemy async."""

from __future__ import annotations

import contextlib
import json
import logging
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from aegisdroid.core.config import DEFAULT_DB_PATH
from aegisdroid.core.domain import (
    Evidence,
    EvidenceType,
    Finding,
    ScanResult,
    ScanType,
    Severity,
    ThreatCategory,
    TimelineEvent,
)

logger = logging.getLogger(__name__)


class _SafeEncoder(json.JSONEncoder):
    """JSON encoder that handles enums and dataclasses."""

    def default(self, o: Any) -> Any:
        if isinstance(o, Enum):
            return o.value
        if hasattr(o, "__dict__"):
            return {k: v for k, v in o.__dict__.items() if not k.startswith("_")}
        if hasattr(o, "isoformat"):
            return o.isoformat()
        return str(o)


class Database:
    """Lightweight async SQLite database."""

    def __init__(self, db_path: str = "") -> None:
        self._db_path = db_path or str(DEFAULT_DB_PATH)
        self._initialized = False
        self._conn: Any = None

    async def initialize(self) -> None:
        if self._initialized:
            return

        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

        try:
            import aiosqlite

            self._conn = await aiosqlite.connect(self._db_path)
            await self._create_tables()
            self._initialized = True
        except ImportError:
            logger.warning("aiosqlite not available, database disabled")
            self._initialized = True

    async def _create_tables(self) -> None:
        if not self._conn:
            return

        await self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                scan_type TEXT,
                device_serial TEXT,
                package_name TEXT,
                started_at TEXT,
                completed_at TEXT,
                findings_json TEXT,
                metadata_json TEXT,
                error TEXT,
                threat_score REAL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT,
                category TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                confidence REAL,
                mitigation TEXT,
                evidence_json TEXT,
                timestamp TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );

            CREATE TABLE IF NOT EXISTS baselines (
                device_serial TEXT PRIMARY KEY,
                data_json TEXT,
                created_at TEXT
            );

            CREATE TABLE IF NOT EXISTS timeline_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                category TEXT,
                title TEXT,
                description TEXT,
                source TEXT,
                severity TEXT,
                metadata_json TEXT
            );

            CREATE TABLE IF NOT EXISTS yara_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT,
                rule_name TEXT,
                namespace TEXT,
                file_path TEXT,
                description TEXT,
                severity TEXT,
                tags_json TEXT,
                timestamp TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            );
        """)
        await self._conn.commit()

    async def save_scan(self, scan_result: ScanResult) -> str:
        if not self._conn:
            return scan_result.id

        findings_json = json.dumps(
            [
                {
                    "id": f.id,
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "confidence": f.confidence,
                    "mitigation": f.mitigation,
                    "evidence": [
                        {
                            "type": e.type.value,
                            "source": e.source,
                            "description": e.description,
                            "confidence": e.confidence,
                        }
                        for e in f.evidence
                    ],
                }
                for f in scan_result.findings
            ]
        )

        await self._conn.execute(
            """INSERT OR REPLACE INTO scans
            (id, scan_type, device_serial, package_name, started_at,
             completed_at, findings_json, metadata_json, error, threat_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_result.id,
                scan_result.scan_type.value,
                scan_result.device_serial,
                scan_result.package_name,
                scan_result.started_at.isoformat(),
                scan_result.completed_at.isoformat() if scan_result.completed_at else None,
                findings_json,
                json.dumps(scan_result.metadata, cls=_SafeEncoder),
                scan_result.error,
                scan_result.threat_confidence_score,
            ),
        )
        await self._conn.commit()
        return scan_result.id

    async def get_scan(self, scan_id: str) -> ScanResult | None:
        if not self._conn:
            return None

        cursor = await self._conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = await cursor.fetchone()
        if not row:
            return None

        return self._row_to_scan(row)

    async def list_scans(self, limit: int = 50) -> list[ScanResult]:
        if not self._conn:
            return []

        cursor = await self._conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
        )
        rows = await cursor.fetchall()
        return [self._row_to_scan(row) for row in rows]

    async def save_baseline(self, device_serial: str, data: dict[str, Any]) -> None:
        if not self._conn:
            return

        await self._conn.execute(
            """INSERT OR REPLACE INTO baselines
            (device_serial, data_json, created_at)
            VALUES (?, ?, ?)""",
            (device_serial, json.dumps(data), datetime.now().replace(tzinfo=None).isoformat()),
        )
        await self._conn.commit()

    async def get_baseline(self, device_serial: str) -> dict[str, Any] | None:
        if not self._conn:
            return None

        cursor = await self._conn.execute(
            "SELECT data_json FROM baselines WHERE device_serial = ?",
            (device_serial,),
        )
        row = await cursor.fetchone()
        if row:
            return json.loads(row[0])
        return None

    async def save_timeline_event(self, event: TimelineEvent) -> None:
        if not self._conn:
            return

        await self._conn.execute(
            """INSERT OR REPLACE INTO timeline_events
            (id, timestamp, category, title, description, source, severity, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event.id,
                event.timestamp.isoformat(),
                event.category,
                event.title,
                event.description,
                event.source,
                event.severity.value,
                json.dumps(event.metadata),
            ),
        )
        await self._conn.commit()

    async def get_timeline(self, limit: int = 100) -> list[TimelineEvent]:
        if not self._conn:
            return []

        cursor = await self._conn.execute(
            "SELECT * FROM timeline_events ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        )
        rows = await cursor.fetchall()
        events = []
        for row in rows:
            events.append(
                TimelineEvent(
                    id=row[0],
                    timestamp=datetime.fromisoformat(row[1]),
                    category=row[2],
                    title=row[3],
                    description=row[4],
                    source=row[5],
                    severity=Severity(row[6]) if row[6] else Severity.INFO,
                    metadata=json.loads(row[7]) if row[7] else {},
                )
            )
        return events

    def _row_to_scan(self, row: Any) -> ScanResult:
        findings_data = json.loads(row[6]) if row[6] else []
        findings = []
        for fd in findings_data:
            evidence = [
                Evidence(
                    type=EvidenceType(e.get("type", "static_analysis")),
                    source=e.get("source", ""),
                    description=e.get("description", ""),
                    confidence=e.get("confidence", 0.0),
                )
                for e in fd.get("evidence", [])
            ]
            findings.append(
                Finding(
                    id=fd.get("id", ""),
                    category=ThreatCategory(fd.get("category", "behavioral_anomaly")),
                    severity=Severity(fd.get("severity", "info")),
                    title=fd.get("title", ""),
                    description=fd.get("description", ""),
                    evidence=evidence,
                    confidence=fd.get("confidence", 0.0),
                    mitigation=fd.get("mitigation", ""),
                )
            )

        return ScanResult(
            id=row[0],
            scan_type=ScanType(row[1]) if row[1] else ScanType.QUICK,
            device_serial=row[2] or "",
            package_name=row[3] or "",
            started_at=datetime.fromisoformat(row[4])
            if row[4]
            else datetime.now().replace(tzinfo=None),
            completed_at=datetime.fromisoformat(row[5]) if row[5] else None,
            findings=findings,
            metadata=json.loads(row[7]) if row[7] else {},
            error=row[8],
        )

    async def close(self) -> None:
        if self._conn:
            with contextlib.suppress(Exception):
                await self._conn.close()
            self._conn = None

"""Filesystem integrity forensics."""

from __future__ import annotations

import logging
from typing import Any

from aegisdroid.core.domain import (
    Evidence,
    EvidenceType,
    Finding,
    Hash,
    Severity,
    ThreatCategory,
)

logger = logging.getLogger(__name__)


class FilesystemForensics:
    """Android filesystem integrity analysis."""

    SYSTEM_PATHS = [
        "/system/bin",
        "/system/xbin",
        "/system/lib",
        "/system/lib64",
        "/system/framework",
        "/system/app",
        "/system/priv-app",
        "/vendor/bin",
        "/vendor/lib",
        "/vendor/lib64",
        "/product/bin",
        "/product/lib",
        "/system_ext/bin",
        "/system_ext/lib",
    ]

    SUSPICIOUS_EXECUTABLE_PATHS = [
        "/data/local/tmp",
        "/sdcard",
        "/storage/emulated/0",
        "/data/data",
        "/data/app",
    ]

    KNOWN_ROOT_FILES = [
        "/system/bin/su",
        "/system/xbin/su",
        "/system/bin/.ext",
        "/system/bin/busybox",
        "/system/xbin/busybox",
        "/data/local/tmp/su",
        "/data/local/tmp/busybox",
        "/system/app/Superuser.apk",
        "/system/app/SuperSU.apk",
        "/system/etc/init.d/99SuperSUDaemon",
    ]

    def __init__(self, adb: Any = None) -> None:
        self._adb = adb
        self._baseline: dict[str, str] = {}

    async def compute_hashes(self, paths: list[str]) -> dict[str, Hash]:
        results: dict[str, Hash] = {}
        if not self._adb:
            return results

        for path in paths:
            out = await self._adb.shell(f"sha256sum {path} 2>/dev/null")
            if out.strip() and " " in out:
                sha256 = out.split()[0]
                results[path] = Hash(sha256=sha256)
        return results

    async def compute_system_hashes(self) -> dict[str, Hash]:
        all_paths: list[str] = []
        for path in self.SYSTEM_PATHS:
            out = await self._adb.shell(
                f"find {path} -type f -name '*.so' -o -name '*.jar' 2>/dev/null | head -200"
            )
            if out.strip():
                all_paths.extend(out.strip().splitlines())

        return await self.compute_hashes(all_paths)

    async def detect_modifications(self, baseline_path: str = "") -> list[Finding]:
        findings = []
        if not self._adb:
            return findings

        if self._baseline:
            current = await self.compute_hashes(list(self._baseline.keys()))
            modified = []
            added = []
            removed = []

            for path, hash_val in current.items():
                if path in self._baseline:
                    if hash_val.sha256 != self._baseline[path]:
                        modified.append((path, self._baseline[path], hash_val.sha256))
                else:
                    added.append(path)

            for path in self._baseline:
                if path not in current:
                    removed.append(path)

            if modified:
                findings.append(
                    Finding(
                        category=ThreatCategory.FILESYSTEM_ANOMALY,
                        severity=Severity.HIGH,
                        title=f"Modified system files detected ({len(modified)})",
                        description=f"{len(modified)} system files have been modified since baseline.",
                        evidence=[
                            Evidence(
                                type=EvidenceType.FILESYSTEM,
                                source="integrity_check",
                                description=f"Modified: {p} (was {old[:16]}..., now {new[:16]}...)",
                                confidence=0.95,
                            )
                            for p, old, new in modified
                        ],
                        confidence=0.9,
                        mitigation="Modified system files may indicate compromise.",
                    )
                )

        return findings

    async def find_suspicious_files(self) -> list[Finding]:
        findings = []
        if not self._adb:
            return findings

        for root_file in self.KNOWN_ROOT_FILES:
            out = await self._adb.shell(f"ls -la {root_file} 2>/dev/null")
            if out.strip() and "No such file" not in out:
                findings.append(
                    Finding(
                        category=ThreatCategory.ROOT,
                        severity=Severity.HIGH,
                        title=f"Root indicator file found: {root_file}",
                        description=f"Found known root-related file: {root_file}",
                        evidence=[
                            Evidence(
                                type=EvidenceType.FILESYSTEM,
                                source="filesystem_scan",
                                description=f"File exists: {root_file} - {out.strip()[:100]}",
                                confidence=0.85,
                            )
                        ],
                        confidence=0.8,
                        mitigation="Known root indicator file present on system.",
                    )
                )

        for path in self.SUSPICIOUS_EXECUTABLE_PATHS:
            out = await self._adb.shell(
                f"find {path} -maxdepth 3 -type f -executable 2>/dev/null | head -20"
            )
            if out.strip():
                files = out.strip().splitlines()
                suspicious = [
                    f for f in files if not f.endswith((".jpg", ".png", ".txt", ".xml", ".json"))
                ]
                if suspicious:
                    findings.append(
                        Finding(
                            category=ThreatCategory.FILESYSTEM_ANOMALY,
                            severity=Severity.MEDIUM,
                            title=f"Executable files in writable location: {path}",
                            description=f"Found {len(suspicious)} executable files in {path}",
                            evidence=[
                                Evidence(
                                    type=EvidenceType.FILESYSTEM,
                                    source="filesystem_scan",
                                    description=f"Executable: {f}",
                                    confidence=0.7,
                                )
                                for f in suspicious[:10]
                            ],
                            confidence=0.6,
                            mitigation="Executable files in writable locations are unusual and may indicate malware.",
                        )
                    )

        out = await self._adb.shell(
            "find /system /vendor /product -name '*.sh' -o -name '*.pl' -o -name '*.py' 2>/dev/null | head -20"
        )
        if out.strip():
            scripts = out.strip().splitlines()
            findings.append(
                Finding(
                    category=ThreatCategory.FILESYSTEM_ANOMALY,
                    severity=Severity.MEDIUM,
                    title=f"Script files found in system partition ({len(scripts)})",
                    description="Script files found in system partitions are unusual.",
                    evidence=[
                        Evidence(
                            type=EvidenceType.FILESYSTEM,
                            source="filesystem_scan",
                            description=f"Script: {s}",
                            confidence=0.6,
                        )
                        for s in scripts[:10]
                    ],
                    confidence=0.5,
                    mitigation="Script files in system partitions may indicate tampering.",
                )
            )

        return findings

    async def analyze_permissions_map(self) -> dict[str, Any]:
        if not self._adb:
            return {}
        out = await self._adb.shell("ls -laR /system/bin/ 2>/dev/null | head -100")
        return {"raw": out}

    async def set_baseline(self) -> dict[str, Hash]:
        self._baseline = await self.compute_system_hashes()
        return self._baseline

    async def find_suid_files(self) -> list[Finding]:
        findings = []
        if not self._adb:
            return findings

        out = await self._adb.shell("find / -perm -4000 -type f 2>/dev/null | head -50")
        if out.strip():
            suid_files = out.strip().splitlines()
            non_standard = [
                f
                for f in suid_files
                if not f.startswith(("/system/bin/su", "/system/bin/toybox", "/system/bin/sh"))
            ]
            if non_standard:
                findings.append(
                    Finding(
                        category=ThreatCategory.FILESYSTEM_ANOMALY,
                        severity=Severity.HIGH,
                        title=f"SUID files found ({len(non_standard)})",
                        description="Non-standard SUID binary files found on the system.",
                        evidence=[
                            Evidence(
                                type=EvidenceType.FILESYSTEM,
                                source="suid_scan",
                                description=f"SUID binary: {f}",
                                confidence=0.8,
                            )
                            for f in non_standard[:10]
                        ],
                        confidence=0.7,
                        mitigation="SUID binaries can escalate privileges to root.",
                    )
                )

        return findings

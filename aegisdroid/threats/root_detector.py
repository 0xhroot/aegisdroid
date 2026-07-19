"""Root detection engine."""

from __future__ import annotations

import logging
from typing import Any

from aegisdroid.core.domain import (
    DeviceInfo,
    Evidence,
    EvidenceType,
    Finding,
    Severity,
    ThreatCategory,
)

logger = logging.getLogger(__name__)


class RootDetector:
    """Comprehensive root and hooking framework detection."""

    def __init__(self, adb: Any = None) -> None:
        self._adb = adb

    async def detect(self, device: DeviceInfo) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(await self.detect_magisk())
        findings.extend(await self.detect_kernelsu())
        findings.extend(await self.detect_apatch())
        findings.extend(await self.detect_frida())
        findings.extend(await self.detect_xposed())
        findings.extend(await self.detect_hooking_frameworks())
        findings.extend(await self._detect_busybox())
        findings.extend(await self._detect_overlayfs())
        findings.extend(await self._detect_suspicious_mounts())
        return findings

    async def detect_magisk(self) -> list[Finding]:
        if not self._adb:
            return []

        findings = []
        checks = [
            ("ls /sbin/.magisk", "Magisk in /sbin"),
            ("ls /data/adb/magisk", "Magisk in /data/adb"),
            ("ls /data/adb/magisk.db", "Magisk database"),
            ("ls /data/adb/modules", "Magisk modules directory"),
            ("which magisk", "Magisk binary in PATH"),
            ("magisk --version 2>/dev/null", "Magisk version command"),
            ("ls /cache/.disable_magisk", "Magisk disable marker"),
            ("getprop init.svc.magisk_pfs", "Magisk persistent service"),
            ("getprop init.svc.magisk_patcher", "Magisk patcher service"),
        ]

        evidence_items = []
        for cmd, desc in checks:
            out = await self._adb.shell(cmd)
            if out.strip() and "No such file" not in out and "not found" not in out.lower():
                evidence_items.append(
                    Evidence(
                        type=EvidenceType.DYNAMIC_ANALYSIS,
                        source="root_detection",
                        description=f"{desc}: {out.strip()[:100]}",
                        confidence=0.9,
                    )
                )

        if evidence_items:
            findings.append(
                Finding(
                    category=ThreatCategory.ROOT,
                    severity=Severity.CRITICAL,
                    title="Magisk root detected",
                    description=(
                        "Device has Magisk root framework installed. "
                        "Magisk provides systemless root and module injection."
                    ),
                    evidence=evidence_items,
                    confidence=0.95,
                    mitigation="Rooted devices have elevated security risks.",
                    references=["https://topjohnwu.github.io/Magisk/"],
                )
            )

        return findings

    async def detect_kernelsu(self) -> list[Finding]:
        if not self._adb:
            return []

        findings = []
        checks = [
            ("ls /data/adb/ksu", "KernelSU directory"),
            ("ls /data/adb/modules/ksu", "KernelSU module"),
            ("which ksud", "KernelSU daemon"),
            ("getprop init.svc.ksud", "KernelSU service"),
            ("cat /proc/version 2>/dev/null | grep -i 'kernelsu'", "KernelSU in kernel"),
        ]

        evidence_items = []
        for cmd, desc in checks:
            out = await self._adb.shell(cmd)
            if out.strip() and "No such file" not in out and "not found" not in out.lower():
                evidence_items.append(
                    Evidence(
                        type=EvidenceType.DYNAMIC_ANALYSIS,
                        source="root_detection",
                        description=f"{desc}: {out.strip()[:100]}",
                        confidence=0.9,
                    )
                )

        if evidence_items:
            findings.append(
                Finding(
                    category=ThreatCategory.ROOT,
                    severity=Severity.CRITICAL,
                    title="KernelSU root detected",
                    description=(
                        "Device has KernelSU root framework. "
                        "KernelSU provides kernel-level root access."
                    ),
                    evidence=evidence_items,
                    confidence=0.92,
                    mitigation="Kernel-level root provides deep system access.",
                )
            )

        return findings

    async def detect_apatch(self) -> list[Finding]:
        if not self._adb:
            return []

        findings = []
        checks = [
            ("ls /data/adb/ap", "APatch directory"),
            ("ls /data/adb/apd", "APatch daemon"),
            ("which apd", "APatch binary"),
            ("getprop init.svc.apd", "APatch service"),
        ]

        evidence_items = []
        for cmd, desc in checks:
            out = await self._adb.shell(cmd)
            if out.strip() and "No such file" not in out and "not found" not in out.lower():
                evidence_items.append(
                    Evidence(
                        type=EvidenceType.DYNAMIC_ANALYSIS,
                        source="root_detection",
                        description=f"{desc}: {out.strip()[:100]}",
                        confidence=0.9,
                    )
                )

        if evidence_items:
            findings.append(
                Finding(
                    category=ThreatCategory.ROOT,
                    severity=Severity.CRITICAL,
                    title="APatch root detected",
                    description="Device has APatch root framework installed.",
                    evidence=evidence_items,
                    confidence=0.9,
                    mitigation="APatch provides kernel-level root access.",
                )
            )

        return findings

    async def detect_frida(self) -> list[Finding]:
        if not self._adb:
            return []

        findings = []
        checks = [
            ("which frida", "Frida binary"),
            ("which frida-server", "Frida server"),
            ("frida --version 2>/dev/null", "Frida version"),
            ("ps -A 2>/dev/null | grep -i frida", "Frida server process"),
            ("ls /data/local/tmp/frida-server", "Frida server binary"),
            ("ls /data/local/tmp/re.frida.server", "Frida server alt"),
            ("netstat -tlnp 2>/dev/null | grep 27042", "Frida default port"),
            ("cat /proc/net/tcp 2>/dev/null | grep 698A", "Frida port hex"),
        ]

        evidence_items = []
        for cmd, desc in checks:
            out = await self._adb.shell(cmd)
            if out.strip() and "No such file" not in out and "not found" not in out.lower():
                evidence_items.append(
                    Evidence(
                        type=EvidenceType.DYNAMIC_ANALYSIS,
                        source="frida_detection",
                        description=f"{desc}: {out.strip()[:100]}",
                        confidence=0.95,
                    )
                )

        if evidence_items:
            findings.append(
                Finding(
                    category=ThreatCategory.FRIDA,
                    severity=Severity.HIGH,
                    title="Frida dynamic instrumentation framework detected",
                    description=(
                        "Frida is a dynamic instrumentation toolkit commonly used "
                        "for runtime hooking, function interception, and bypassing "
                        "security controls."
                    ),
                    evidence=evidence_items,
                    confidence=0.92,
                    mitigation="Frida can bypass app security controls and extract data at runtime.",
                    references=["https://frida.re"],
                )
            )

        return findings

    async def detect_xposed(self) -> list[Finding]:
        if not self._adb:
            return []

        findings = []
        checks = [
            ("ls /system/framework/XposedBridge.jar", "Xposed framework"),
            ("ls /data/misc/riru/modules/", "Riru modules"),
            ("getprop dalvik.vm.dex2oat-Xms 2>/dev/null", "Xposed property"),
            ("ls /data/adb/lspd", "LSPosed directory"),
            ("ls /data/adb/modules/lsposed", "LSPosed module"),
            ("which lsposed", "LSPosed binary"),
            ("ls /data/adb/edxposed", "EdXposed directory"),
            ("getprop init.svc.edxposed_manager", "EdXposed service"),
        ]

        evidence_items = []
        frameworks_found = set()
        for cmd, desc in checks:
            out = await self._adb.shell(cmd)
            if out.strip() and "No such file" not in out and "not found" not in out.lower():
                evidence_items.append(
                    Evidence(
                        type=EvidenceType.DYNAMIC_ANALYSIS,
                        source="xposed_detection",
                        description=f"{desc}: {out.strip()[:100]}",
                        confidence=0.85,
                    )
                )
                if "lsposed" in desc.lower():
                    frameworks_found.add("LSPosed")
                elif "edxposed" in desc.lower():
                    frameworks_found.add("EdXposed")
                elif "xposed" in desc.lower():
                    frameworks_found.add("Xposed")
                elif "riru" in desc.lower():
                    frameworks_found.add("Riru")

        if evidence_items:
            fw_list = ", ".join(frameworks_found) if frameworks_found else "Xposed variant"
            findings.append(
                Finding(
                    category=ThreatCategory.XPOSED,
                    severity=Severity.HIGH,
                    title=f"Xposed framework detected ({fw_list})",
                    description=(
                        f"Device has {fw_list} installed. Xposed frameworks allow "
                        f"runtime modification of app behavior and system properties."
                    ),
                    evidence=evidence_items,
                    confidence=0.88,
                    mitigation="Xposed frameworks can bypass security controls and modify app behavior.",
                )
            )

        return findings

    async def detect_hooking_frameworks(self) -> list[Finding]:
        if not self._adb:
            return []

        findings = []
        checks = [
            ("ls /data/local/tmp/Substrate", "Cydia Substrate"),
            ("ls /data/local/tmp/libsubstrate.so", "Substrate library"),
            ("getprop init.svc.ss_helper", "Substrate service"),
            ("which riru", "Riru"),
            ("ls /data/adb/riru", "Riru directory"),
            ("ls /data/adb/modules/riru-core", "Riru core module"),
        ]

        evidence_items = []
        for cmd, desc in checks:
            out = await self._adb.shell(cmd)
            if out.strip() and "No such file" not in out and "not found" not in out.lower():
                evidence_items.append(
                    Evidence(
                        type=EvidenceType.DYNAMIC_ANALYSIS,
                        source="hooking_detection",
                        description=f"{desc}: {out.strip()[:100]}",
                        confidence=0.85,
                    )
                )

        if evidence_items:
            findings.append(
                Finding(
                    category=ThreatCategory.HOOKING_FRAMEWORK,
                    severity=Severity.HIGH,
                    title="Hooking framework detected",
                    description="Device has hooking framework components installed.",
                    evidence=evidence_items,
                    confidence=0.85,
                    mitigation="Hooking frameworks can intercept and modify function calls.",
                )
            )

        return findings

    async def _detect_busybox(self) -> list[Finding]:
        if not self._adb:
            return []

        findings = []
        out = await self._adb.shell("which busybox")
        if out.strip() and "not found" not in out.lower():
            findings.append(
                Finding(
                    category=ThreatCategory.ROOT,
                    severity=Severity.MEDIUM,
                    title="BusyBox detected",
                    description=(
                        "BusyBox is commonly installed on rooted devices and "
                        "provides Unix utilities that can aid in system modification."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.DYNAMIC_ANALYSIS,
                            source="root_detection",
                            description=f"BusyBox binary: {out.strip()}",
                            confidence=0.8,
                        )
                    ],
                    confidence=0.7,
                    mitigation="BusyBox is a common indicator of rooted devices.",
                )
            )
        return findings

    async def _detect_overlayfs(self) -> list[Finding]:
        if not self._adb:
            return []

        findings = []
        out = await self._adb.shell("mount | grep overlay")
        if out.strip() and "overlay" in out.lower():
            findings.append(
                Finding(
                    category=ThreatCategory.ROOT,
                    severity=Severity.HIGH,
                    title="OverlayFS detected",
                    description=(
                        "OverlayFS is mounted, indicating filesystem layering. "
                        "This is commonly used by root solutions to modify "
                        "system partitions without altering them."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.DYNAMIC_ANALYSIS,
                            source="filesystem_analysis",
                            description=f"Overlay mount: {out.strip()[:200]}",
                            confidence=0.9,
                        )
                    ],
                    confidence=0.85,
                    mitigation="OverlayFS can mask modifications to system files.",
                )
            )
        return findings

    async def _detect_suspicious_mounts(self) -> list[Finding]:
        if not self._adb:
            return []

        findings = []
        out = await self._adb.shell("mount")
        suspicious_patterns = ["su/su", "/magisk", "/ksu", "/apatch", "/data/adb/modules"]
        found_mounts = []
        for line in out.strip().splitlines():
            for pattern in suspicious_patterns:
                if pattern in line.lower():
                    found_mounts.append(line.strip())
                    break

        if found_mounts:
            findings.append(
                Finding(
                    category=ThreatCategory.ROOT,
                    severity=Severity.HIGH,
                    title="Suspicious filesystem mounts detected",
                    description="Found suspicious mount points indicating root framework activity.",
                    evidence=[
                        Evidence(
                            type=EvidenceType.DYNAMIC_ANALYSIS,
                            source="filesystem_analysis",
                            description=f"Suspicious mount: {m}",
                            confidence=0.85,
                        )
                        for m in found_mounts
                    ],
                    confidence=0.8,
                    mitigation="Suspicious mounts indicate filesystem modification.",
                )
            )
        return findings

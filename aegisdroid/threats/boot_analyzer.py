"""Boot chain security analysis."""

from __future__ import annotations

import logging
from typing import Any

from aegisdroid.core.domain import (
    Evidence,
    EvidenceType,
    Finding,
    Severity,
    ThreatCategory,
)

logger = logging.getLogger(__name__)


class BootAnalyzer:
    """Analyze boot chain integrity: AVB, DM-Verity, Verified Boot."""

    def __init__(self, adb: Any = None) -> None:
        self._adb = adb

    async def analyze_boot(self) -> dict[str, Any]:
        if not self._adb:
            return {}
        result: dict[str, Any] = {}
        result["avb"] = await self.check_avb()
        result["dm_verity"] = await self.check_dm_verity()
        result["vbmeta"] = await self.analyze_vbmeta()
        result["rollback_index"] = await self.get_rollback_index()
        result["bootloader"] = await self._check_bootloader()
        result["oem_unlock"] = await self._check_oem_unlock()
        return result

    async def analyze_vbmeta(self) -> dict[str, Any]:
        if not self._adb:
            return {}
        result: dict[str, Any] = {}
        props = [
            "ro.boot.vbmeta.digest",
            "ro.boot.vbmeta.avb_version",
            "ro.boot.vbmeta.device_state",
        ]
        for prop in props:
            val = await self._adb.get_property(prop)
            result[prop.split(".")[-1]] = val

        out = await self._adb.shell("cat /proc/cmdline")
        if "vbmeta" in out.lower():
            result["cmdline_vbmeta"] = out[:500]
        return result

    async def check_avb(self) -> dict[str, Any]:
        if not self._adb:
            return {}
        result: dict[str, Any] = {}
        checks = [
            "avbctl verify 2>/dev/null",
            "ls /dev/block/by-name/vbmeta*",
            "cat /dev/block/by-name/vbmeta 2>/dev/null | head -c 256 | hexdump -C 2>/dev/null",
        ]
        for cmd in checks:
            out = await self._adb.shell(cmd)
            if out.strip() and "not found" not in out.lower():
                result[cmd.split()[0]] = out.strip()[:200]

        avb_status = await self._adb.shell("avbctl verify 2>/dev/null")
        result["status"] = avb_status.strip() if avb_status else "unknown"
        return result

    async def check_dm_verity(self) -> dict[str, Any]:
        if not self._adb:
            return {}
        result: dict[str, Any] = {}
        out = await self._adb.shell("mount | grep dm-verity")
        result["mounted"] = bool(out.strip())
        result["mount_info"] = out.strip()[:200] if out else ""

        prop = await self._adb.get_property("ro.boot.verifiedbootstate")
        result["verified_boot_state"] = prop

        prop2 = await self._adb.get_property("ro.boot.flash.locked")
        result["flash_locked"] = prop2

        return result

    async def get_rollback_index(self) -> int:
        if not self._adb:
            return -1
        out = await self._adb.shell(
            "cat /sys/class/android_usb/android0/rollback_index 2>/dev/null"
        )
        try:
            return int(out.strip())
        except (ValueError, AttributeError):
            return -1

    async def _check_bootloader(self) -> dict[str, str]:
        if not self._adb:
            return {}
        result = {}
        result["bootloader"] = await self._adb.get_property("ro.bootloader")
        result["secure_boot"] = await self._adb.get_property("ro.secureboot")
        result["verified_boot_state"] = await self._adb.get_property("ro.boot.verifiedbootstate")
        return result

    async def _check_oem_unlock(self) -> dict[str, str]:
        if not self._adb:
            return {}
        result = {}
        result["oem_unlock_supported"] = await self._adb.get_property("ro.boot.oemunlock-supported")
        result["oem_unlock_allowed"] = await self._adb.get_property("ro.oem_unlock_supported")
        prop = await self._adb.shell("cat /data/misc/keystore/user_unlock_key 2>/dev/null")
        result["unlock_key"] = "present" if prop.strip() else "absent"
        return result

    async def detect_boot_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        if not self._adb:
            return findings

        boot_data = await self.analyze_boot()
        boot_data.get("vbmeta", {})
        dm_verity = boot_data.get("dm_verity", {})
        boot_data.get("avb", {})
        bootloader = boot_data.get("bootloader", {})
        boot_data.get("oem_unlock", {})

        if dm_verity.get("verified_boot_state") in ("orange", "red"):
            findings.append(
                Finding(
                    category=ThreatCategory.BOOT_TAMPER,
                    severity=Severity.CRITICAL,
                    title=f"Verified boot state: {dm_verity['verified_boot_state']}",
                    description=(
                        f"Device is in '{dm_verity['verified_boot_state']}' boot state. "
                        f"This means the bootloader is unlocked and the device "
                        f"may be running modified firmware."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.BOOT,
                            source="boot_analysis",
                            description=f"Verified boot state: {dm_verity['verified_boot_state']}",
                            confidence=0.95,
                        )
                    ],
                    confidence=0.95,
                    mitigation="Unlocking bootloader weakens Verified Boot protections.",
                )
            )

        if bootloader.get("secure_boot") == "0":
            findings.append(
                Finding(
                    category=ThreatCategory.BOOT_TAMPER,
                    severity=Severity.HIGH,
                    title="Secure boot disabled",
                    description="Device has secure boot disabled.",
                    evidence=[
                        Evidence(
                            type=EvidenceType.BOOT,
                            source="boot_analysis",
                            description="ro.secureboot=0",
                            confidence=0.9,
                        )
                    ],
                    confidence=0.85,
                    mitigation="Secure boot ensures only signed code runs during boot.",
                )
            )

        if dm_verity.get("flash_locked") == "0":
            findings.append(
                Finding(
                    category=ThreatCategory.BOOT_TAMPER,
                    severity=Severity.HIGH,
                    title="Bootloader unlocked",
                    description="Device bootloader is unlocked.",
                    evidence=[
                        Evidence(
                            type=EvidenceType.BOOT,
                            source="boot_analysis",
                            description="Bootloader flash lock state: unlocked",
                            confidence=0.95,
                        )
                    ],
                    confidence=0.95,
                    mitigation="Unlocked bootloader allows installation of custom firmware.",
                )
            )

        rollback = boot_data.get("rollback_index", -1)
        if rollback == 0:
            findings.append(
                Finding(
                    category=ThreatCategory.BOOT_TAMPER,
                    severity=Severity.MEDIUM,
                    title="Rollback index is zero",
                    description="Device rollback protection index is 0, indicating no anti-rollback protection.",
                    evidence=[
                        Evidence(
                            type=EvidenceType.BOOT,
                            source="boot_analysis",
                            description="Rollback index: 0",
                            confidence=0.8,
                        )
                    ],
                    confidence=0.7,
                    mitigation="Anti-rollback prevents downgrade attacks.",
                )
            )

        return findings

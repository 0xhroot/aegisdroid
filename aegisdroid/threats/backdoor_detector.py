"""Backdoor and persistence detection engine."""

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

KNOWN_BACKDOOR_PATHS = [
    "/system/bin/backdoor",
    "/system/xbin/backdoor",
    "/data/local/tmp/backdoor",
    "/data/local/tmp/rat",
    "/system/etc/.hidden",
    "/system/.hidden",
    "/data/adb/post-fs-data.d",
    "/data/adb/service.d",
    "/system/addon.d",
    "/system/etc/init.d",
    "/system/etc/perf-profile",
]

PERSISTENCE_LOCATIONS = [
    "/system/etc/init/",
    "/vendor/etc/init/",
    "/system/etc/init.d/",
    "/data/adb/service.d/",
    "/data/adb/post-fs-data.d/",
]

HIDDEN_DIR_PATHS = [
    "/data/local/tmp/.hidden",
    "/sdcard/.hidden",
    "/data/data/.hidden",
    "/system/.hidden",
    "/data/local/tmp/.backup",
]


class BackdoorDetector:
    """Detects backdoors, persistence mechanisms, and hidden components."""

    def __init__(self, adb: Any = None) -> None:
        self._adb = adb

    async def scan(self) -> list[Finding]:
        findings: list[Finding] = []

        if not self._adb:
            return findings

        findings.extend(await self._check_persistence_mechanisms())
        findings.extend(await self._check_hidden_directories())
        findings.extend(await self._check_suspicious_init_scripts())
        findings.extend(await self._check_adb_over_network())
        findings.extend(await self._check_debug_properties())
        findings.extend(await self._check_emergency_dialer())
        findings.extend(await self._check_hidden_processes())
        findings.extend(await self._check_bind_mounts())
        findings.extend(await self._check_custom_keys())
        findings.extend(await self._check_screen_lock_bypass())

        return findings

    async def _check_persistence_mechanisms(self) -> list[Finding]:
        findings = []
        for loc in PERSISTENCE_LOCATIONS:
            out = await self._adb.shell(f"ls -la {loc} 2>/dev/null")
            if out.strip() and "No such file" not in out:
                files = [
                    f.strip()
                    for f in out.strip().splitlines()
                    if f.strip() and not f.strip().startswith("total")
                ]
                if files:
                    findings.append(
                        Finding(
                            category=ThreatCategory.PERSISTENCE,
                            severity=Severity.HIGH,
                            title=f"Custom init scripts in {loc}",
                            description=(
                                f"Found {len(files)} custom init scripts in {loc}. "
                                f"These execute automatically at boot and may establish persistence."
                            ),
                            evidence=[
                                Evidence(
                                    type=EvidenceType.FILESYSTEM,
                                    source="persistence_scan",
                                    description=f"Init script: {f[:100]}",
                                    confidence=0.8,
                                )
                                for f in files[:10]
                            ],
                            confidence=0.75,
                            mitigation="Review all init scripts. Remove any that are not authorized.",
                        )
                    )
        return findings

    async def _check_hidden_directories(self) -> list[Finding]:
        findings = []
        hidden = []
        for path in HIDDEN_DIR_PATHS:
            out = await self._adb.shell(f"ls -la {path} 2>/dev/null")
            if out.strip() and "No such file" not in out:
                hidden.append(path)

        for path in KNOWN_BACKDOOR_PATHS:
            out = await self._adb.shell(f"ls -la {path} 2>/dev/null")
            if out.strip() and "No such file" not in out:
                hidden.append(path)

        # Also check for hidden dirs in common locations
        extra = await self._adb.shell(
            "find /data/local/tmp /sdcard -maxdepth 2 -name '.*' -type d 2>/dev/null | head -10"
        )
        if extra.strip():
            hidden.extend(extra.strip().splitlines())

        if hidden:
            findings.append(
                Finding(
                    category=ThreatCategory.BACKDOOR,
                    severity=Severity.HIGH,
                    title=f"Hidden or suspicious directories ({len(hidden)})",
                    description=(
                        f"Found {len(hidden)} hidden or suspicious directories that "
                        f"may contain backdoor components or stolen data."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.FILESYSTEM,
                            source="backdoor_scan",
                            description=f"Hidden directory: {d}",
                            confidence=0.7,
                        )
                        for d in hidden[:10]
                    ],
                    confidence=0.7,
                    mitigation="Investigate contents of hidden directories.",
                )
            )
        return findings

    async def _check_suspicious_init_scripts(self) -> list[Finding]:
        findings = []
        out = await self._adb.shell(
            "find /system/etc/init.d /data/adb/service.d /data/adb/post-fs-data.d "
            "-type f -executable 2>/dev/null"
        )
        if out.strip():
            scripts = out.strip().splitlines()
            findings.append(
                Finding(
                    category=ThreatCategory.PERSISTENCE,
                    severity=Severity.HIGH,
                    title=f"Executable init scripts found ({len(scripts)})",
                    description=(
                        f"Found {len(scripts)} executable scripts that run at boot. "
                        f"These can establish persistent backdoors."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.FILESYSTEM,
                            source="init_script_scan",
                            description=f"Script: {s}",
                            confidence=0.8,
                        )
                        for s in scripts[:10]
                    ],
                    confidence=0.75,
                    mitigation="Review and remove unauthorized init scripts.",
                )
            )
        return findings

    async def _check_adb_over_network(self) -> list[Finding]:
        findings = []
        tcpip = await self._adb.shell("getprop service.adb.tcp.port 2>/dev/null")
        if tcpip.strip() and tcpip.strip() != "0" and "null" not in tcpip.lower():
            findings.append(
                Finding(
                    category=ThreatCategory.BACKDOOR,
                    severity=Severity.HIGH,
                    title="ADB over network (TCP) enabled",
                    description=(
                        f"ADB TCP port is set to '{tcpip.strip()}'. "
                        f"This allows wireless ADB connections which can be exploited."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.STATIC_ANALYSIS,
                            source="adb_config_scan",
                            description=f"ADB TCP port: {tcpip.strip()}",
                            confidence=0.9,
                        )
                    ],
                    confidence=0.9,
                    mitigation=("Disable ADB over TCP: adb shell setprop service.adb.tcp.port 0"),
                )
            )

        netprop = await self._adb.shell("getprop persist.adb.tcp.port 2>/dev/null")
        if netprop.strip() and netprop.strip() != "0":
            findings.append(
                Finding(
                    category=ThreatCategory.BACKDOOR,
                    severity=Severity.CRITICAL,
                    title="Persistent ADB over network enabled",
                    description=(
                        f"ADB TCP is persistently set to '{netprop.strip()}'. "
                        f"This survives reboots and enables remote access."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.STATIC_ANALYSIS,
                            source="adb_config_scan",
                            description=f"Persistent ADB TCP port: {netprop.strip()}",
                            confidence=0.95,
                        )
                    ],
                    confidence=0.95,
                    mitigation="Run: adb shell setprop persist.adb.tcp.port 0",
                )
            )
        return findings

    async def _check_debug_properties(self) -> list[Finding]:
        findings = []
        debug_props = [
            ("ro.debuggable", "1"),
            ("ro.secure", "0"),
            ("ro.adb.secure", "0"),
            ("persist.sys.usb.config", "adb"),
        ]

        for prop, bad_val in debug_props:
            val = await self._adb.shell(f"getprop {prop} 2>/dev/null")
            val = val.strip()
            if val == bad_val:
                findings.append(
                    Finding(
                        category=ThreatCategory.PRIVILEGE_ESCALATION,
                        severity=Severity.MEDIUM if prop != "ro.secure" else Severity.HIGH,
                        title=f"Debug property enabled: {prop}={val}",
                        description=(
                            f"Property '{prop}' is set to '{val}', which may weaken "
                            f"device security."
                        ),
                        evidence=[
                            Evidence(
                                type=EvidenceType.STATIC_ANALYSIS,
                                source="property_scan",
                                description=f"{prop} = {val}",
                                confidence=0.9,
                            )
                        ],
                        confidence=0.85,
                        mitigation=f"Set '{prop}' to a more secure value.",
                    )
                )
        return findings

    async def _check_emergency_dialer(self) -> list[Finding]:
        findings = []
        admin = await self._adb.shell(
            "dumpsys device_policy 2>/dev/null | grep -i 'admin\\|owner\\|restrict' | head -10"
        )
        if admin.strip():
            findings.append(
                Finding(
                    category=ThreatCategory.PERSISTENCE,
                    severity=Severity.LOW,
                    title="Device admin policies active",
                    description="Device admin or MDM policies are active on this device.",
                    evidence=[
                        Evidence(
                            type=EvidenceType.STATIC_ANALYSIS,
                            source="device_policy_scan",
                            description=f"Policy: {line.strip()[:100]}",
                            confidence=0.6,
                        )
                        for line in admin.strip().splitlines()[:5]
                    ],
                    confidence=0.5,
                    mitigation="Verify device admin policies are authorized.",
                )
            )
        return findings

    async def _check_hidden_processes(self) -> list[Finding]:
        findings: list[Finding] = []
        ps = await self._adb.shell("ps -A -o NAME 2>/dev/null | grep -v '^NAME'")
        if not ps.strip():
            return findings

        known_system = {
            "init",
            "kthreadd",
            "ksoftirqd",
            "rcu_preempt",
            "migration",
            "watchdog",
            "kworker",
            "rcu_sched",
            "rcuog",
            "rcuop",
            "system_server",
            "zygote",
            "zygote64",
            "servicemanager",
            "vold",
            "netd",
            "installd",
            "logd",
            "lmkd",
            "healthd",
            "adbd",
            "shell",
            "logcat",
        }

        suspicious = []
        for line in ps.strip().splitlines():
            name = line.strip()
            if name and name not in known_system and not name.startswith("["):
                if any(
                    c in name.lower()
                    for c in ["shell", "cmd", "exec", "spawn", "reverse", "tunnel", "proxy", "bind"]
                ):
                    suspicious.append(name)

        if suspicious:
            findings.append(
                Finding(
                    category=ThreatCategory.BACKDOOR,
                    severity=Severity.HIGH,
                    title=f"Suspicious process names detected ({len(suspicious)})",
                    description="Found processes with names commonly associated with backdoors.",
                    evidence=[
                        Evidence(
                            type=EvidenceType.DYNAMIC_ANALYSIS,
                            source="process_scan",
                            description=f"Suspicious process: {p}",
                            confidence=0.7,
                        )
                        for p in suspicious[:10]
                    ],
                    confidence=0.65,
                    mitigation="Investigate these processes and their parent processes.",
                )
            )
        return findings

    async def _check_bind_mounts(self) -> list[Finding]:
        findings = []
        mounts = await self._adb.shell("cat /proc/mounts 2>/dev/null | grep -E 'bind|override'")
        if mounts.strip():
            bind_mounts = [
                m
                for m in mounts.strip().splitlines()
                if "bind" in m.lower() or "override" in m.lower()
            ]
            if bind_mounts:
                findings.append(
                    Finding(
                        category=ThreatCategory.BACKDOOR,
                        severity=Severity.MEDIUM,
                        title=f"Bind mounts detected ({len(bind_mounts)})",
                        description=(
                            "Bind mounts can overlay filesystems to hide modifications "
                            "or inject malicious content."
                        ),
                        evidence=[
                            Evidence(
                                type=EvidenceType.FILESYSTEM,
                                source="mount_scan",
                                description=f"Bind mount: {m[:120]}",
                                confidence=0.7,
                            )
                            for m in bind_mounts[:10]
                        ],
                        confidence=0.6,
                        mitigation="Verify bind mounts are legitimate and not hiding modifications.",
                    )
                )
        return findings

    async def _check_custom_keys(self) -> list[Finding]:
        findings = []
        keys = await self._adb.shell("ls -la /data/misc/adb/ 2>/dev/null")
        if keys.strip() and "No such file" not in keys:
            key_files = [f for f in keys.strip().splitlines() if f.strip() and ".pub" in f]
            if key_files:
                findings.append(
                    Finding(
                        category=ThreatCategory.PERSISTENCE,
                        severity=Severity.MEDIUM,
                        title=f"Custom ADB keys installed ({len(key_files)})",
                        description=(
                            "Custom ADB authorized keys found. These allow passwordless "
                            "ADB access and may indicate unauthorized access."
                        ),
                        evidence=[
                            Evidence(
                                type=EvidenceType.STATIC_ANALYSIS,
                                source="adb_key_scan",
                                description=f"Key: {k.strip()[:100]}",
                                confidence=0.85,
                            )
                            for k in key_files[:5]
                        ],
                        confidence=0.7,
                        mitigation="Review authorized ADB keys and remove unknown ones.",
                    )
                )
        return findings

    async def _check_screen_lock_bypass(self) -> list[Finding]:
        findings = []
        lock = await self._adb.shell("settings get secure lockscreen.disabled 2>/dev/null")
        if lock.strip() == "1":
            findings.append(
                Finding(
                    category=ThreatCategory.PERSISTENCE,
                    severity=Severity.MEDIUM,
                    title="Screen lock disabled",
                    description=(
                        "Screen lock is disabled, which may allow unauthorized "
                        "physical access to the device."
                    ),
                    evidence=[
                        Evidence(
                            type=EvidenceType.STATIC_ANALYSIS,
                            source="security_scan",
                            description="lockscreen.disabled = 1",
                            confidence=0.9,
                        )
                    ],
                    confidence=0.85,
                    mitigation="Enable screen lock for physical security.",
                )
            )
        return findings

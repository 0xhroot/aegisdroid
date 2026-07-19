"""ADB adapter - communicates with Android devices via ADB."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from aegisdroid.core.config import ADBConfig
from aegisdroid.core.domain import DeviceInfo
from aegisdroid.core.events import Event, Events, event_bus
from aegisdroid.core.interfaces import ADBPort

logger = logging.getLogger(__name__)


class ADBAdapter(ADBPort):
    """Async ADB adapter using subprocess."""

    def __init__(self, config: ADBConfig | None = None) -> None:
        self._config = config or ADBConfig()
        self._serial: str = ""
        self._connected = False

    def _adb_cmd(self, *args: str) -> list[str]:
        cmd = [self._config.adb_path]
        if self._serial:
            cmd.extend(["-s", self._serial])
        cmd.extend(args)
        return cmd

    async def _run(self, cmd: list[str], timeout: float = 30.0) -> tuple[int, str, str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return (
                proc.returncode or 0,
                stdout.decode("utf-8", errors="replace"),
                stderr.decode("utf-8", errors="replace"),
            )
        except TimeoutError:
            logger.warning("ADB command timed out: %s", " ".join(cmd))
            return (-1, "", "timeout")
        except FileNotFoundError:
            logger.exception("ADB binary not found at: %s", self._config.adb_path)
            return (-1, "", f"adb not found: {self._config.adb_path}")

    async def connect(self, serial: str = "") -> bool:
        if serial:
            self._serial = serial
        elif not self._serial:
            devices = await self.list_devices()
            if not devices:
                logger.error("No ADB devices found")
                return False
            self._serial = devices[0].get("serial", "")

        rc, out, err = await self._run(self._adb_cmd("get-state"))
        if rc == 0 and "device" in out:
            self._connected = True
            await event_bus.publish(
                Event(
                    name=Events.DEVICE_CONNECTED,
                    data={"serial": self._serial},
                    source="adb",
                )
            )
            logger.info("Connected to device: %s", self._serial)
            return True
        logger.error("Failed to connect: %s", err.strip())
        return False

    async def disconnect(self) -> None:
        if self._serial:
            await event_bus.publish(
                Event(
                    name=Events.DEVICE_DISCONNECTED,
                    data={"serial": self._serial},
                    source="adb",
                )
            )
        self._connected = False
        self._serial = ""

    async def execute(self, command: str, timeout: float = 30.0) -> tuple[int, str, str]:
        return await self._run(self._adb_cmd("exec-out", command), timeout)

    async def shell(self, command: str, timeout: float = 30.0) -> str:
        rc, out, err = await self._run(self._adb_cmd("shell", command), timeout)
        if rc != 0:
            logger.debug("ADB shell error: %s", err.strip())
        return out

    async def pull(self, remote: str, local: str) -> bool:
        rc, _, _err = await self._run(self._adb_cmd("pull", remote, local), timeout=120)
        return rc == 0

    async def push(self, local: str, remote: str) -> bool:
        rc, _, _err = await self._run(self._adb_cmd("push", local, remote), timeout=120)
        return rc == 0

    async def list_devices(self) -> list[dict[str, str]]:
        _rc, out, _ = await self._run(self._adb_cmd("devices", "-l"))
        devices: list[dict[str, str]] = []
        for line in out.strip().splitlines()[1:]:
            line = line.strip()
            if not line or "offline" in line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                serial = parts[0]
                state_str = parts[1]
                info = {"serial": serial, "state": state_str}
                for part in parts[2:]:
                    if ":" in part:
                        k, v = part.split(":", 1)
                        info[k] = v
                devices.append(info)
        return devices

    async def get_device_info(self) -> DeviceInfo:
        props = {}
        prop_keys = [
            "ro.product.model",
            "ro.product.manufacturer",
            "ro.product.brand",
            "ro.product.device",
            "ro.product.board",
            "ro.product.hardware",
            "ro.build.version.release",
            "ro.build.version.sdk",
            "ro.build.display.id",
            "ro.build.fingerprint",
            "ro.build.type",
            "ro.build.tags",
            "ro.build.version.security_patch",
            "ro.kernel.version",
            "gsm.version.baseband",
            "ro.boot.serialno",
            "ro.boot.hardware.sku",
            "ro.bootloader",
            "ro.hardware",
        ]
        for key in prop_keys:
            props[key] = (await self.get_property(key)).strip()

        sdk = int(props.get("ro.build.version.sdk", "0") or "0")
        fingerprint = props.get("ro.build.fingerprint", "")
        is_emulator = any(
            x in fingerprint.lower() for x in ["generic", "sdk", "emulator", "goldfish", "ranchu"]
        )

        return DeviceInfo(
            serial=self._serial,
            model=props.get("ro.product.model", ""),
            manufacturer=props.get("ro.product.manufacturer", ""),
            brand=props.get("ro.product.brand", ""),
            device=props.get("ro.product.device", ""),
            board=props.get("ro.product.board", ""),
            hardware=props.get("ro.product.hardware", ""),
            android_version=props.get("ro.build.version.release", ""),
            sdk_level=sdk,
            build_id=props.get("ro.build.display.id", ""),
            build_fingerprint=fingerprint,
            build_type=props.get("ro.build.type", ""),
            build_tags=props.get("ro.build.tags", ""),
            security_patch=props.get("ro.build.version.security_patch", ""),
            kernel_version=props.get("ro.kernel.version", ""),
            baseband=props.get("gsm.version.baseband", ""),
            bootloader=props.get("ro.bootloader", ""),
            serial_number=props.get("ro.boot.serialno", self._serial),
            is_emulator=is_emulator,
            properties=props,
        )

    async def get_property(self, prop: str) -> str:
        return (await self.shell(f"getprop {prop}")).strip()

    async def is_rooted(self) -> bool:
        checks = [
            "which su",
            "ls /system/xbin/su",
            "ls /system/bin/su",
            "which magisk",
            "ls /data/adb/magisk",
        ]
        for cmd in checks:
            out = await self.shell(cmd)
            if out.strip() and "not found" not in out.lower():
                return True
        return False

    async def get_installed_packages(self) -> list[str]:
        out = await self.shell("pm list packages -f")
        packages = []
        for line in out.strip().splitlines():
            if line.startswith("package:"):
                packages.append(line.split(":", 1)[1])
        return packages

    async def get_package_path(self, package: str) -> str:
        out = await self.shell(f"pm path {package}")
        for line in out.strip().splitlines():
            if line.startswith("package:"):
                return line.split(":", 1)[1]
        return ""

    async def dumpsys(self, service: str) -> str:
        return await self.shell(f"dumpsys {service}")

    async def get_logcat(self, buffer: str = "main", lines: int = 1000) -> str:
        return await self.shell(f"logcat -b {buffer} -d -t {lines}")

    async def run_as(self, package: str, command: str) -> str:
        return await self.shell(f"run-as {package} {command}")

    async def get_process_list(self) -> list[dict[str, str]]:
        out = await self.shell("ps -A -o PID,USER,NAME")
        processes = []
        for line in out.strip().splitlines()[1:]:
            parts = line.split(None, 2)
            if len(parts) >= 3:
                processes.append(
                    {
                        "pid": parts[0],
                        "user": parts[1],
                        "name": parts[2],
                    }
                )
        return processes

    async def get_network_info(self) -> dict[str, Any]:
        out = await self.shell("cat /proc/net/tcp")
        out6 = await self.shell("cat /proc/net/tcp6")
        return {"tcp": out, "tcp6": out6}

    async def get_battery_info(self) -> dict[str, str]:
        out = await self.shell("dumpsys battery")
        info = {}
        for line in out.strip().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                info[k.strip()] = v.strip()
        return info

    async def get_storage_info(self) -> list[dict[str, str]]:
        out = await self.shell("df -h /data /system /vendor")
        entries = []
        for line in out.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 6:
                entries.append(
                    {
                        "filesystem": parts[0],
                        "size": parts[1],
                        "used": parts[2],
                        "available": parts[3],
                        "use_percent": parts[4],
                        "mount": parts[5],
                    }
                )
        return entries

    async def get_accessibility_services(self) -> list[str]:
        out = await self.shell("settings get secure enabled_accessibility_services")
        services = out.strip()
        if services and services != "null":
            return [s.strip() for s in services.split(":") if s.strip()]
        return []

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def current_serial(self) -> str:
        return self._serial

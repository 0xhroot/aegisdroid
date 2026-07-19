"""Comprehensive device profiling for forensic analysis."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class DeviceProfiler:
    """Collects comprehensive device information via ADB."""

    def __init__(self, adb: Any) -> None:
        self._adb = adb

    async def profile_device(self) -> dict[str, Any]:
        """Full device profiling — OS, hardware, security, crypto, accounts, etc."""
        profile: dict[str, Any] = {}

        sections = [
            ("hardware", self._get_hardware_info),
            ("os", self._get_os_info),
            ("kernel", self._get_kernel_info),
            ("security", self._get_security_profile),
            ("crypto", self._get_crypto_info),
            ("network", self._get_network_profile),
            ("users", self._get_user_accounts),
            ("accounts", self._get_sync_accounts),
            ("storage", self._get_storage_detail),
            ("battery", self._get_battery_detail),
            ("display", self._get_display_info),
            ("telephony", self._get_telephony_info),
            ("usb", self._get_usb_info),
            ("bluetooth", self._get_bluetooth_info),
            ("location", self._get_location_providers),
            ("accessibility", self._get_accessibility_detail),
            ("device_admins", self._get_device_admins),
            ("input_methods", self._get_input_methods),
            ("launchers", self._get_launcher_apps),
            ("packages", self._get_package_summary),
            ("running_services", self._get_running_services),
            ("processes", self._get_process_snapshot),
            ("mounts", self._get_mount_info),
            ("selinux", self._get_selinux_status),
            ("system_properties", self._get_all_properties),
        ]

        for key, func in sections:
            try:
                profile[key] = await func()
            except Exception as e:
                logger.debug("Failed to get %s: %s", key, e)
                profile[key] = {"error": str(e)}

        return profile

    async def _get_hardware_info(self) -> dict[str, Any]:
        return {
            "model": await self._prop("ro.product.model"),
            "manufacturer": await self._prop("ro.product.manufacturer"),
            "brand": await self._prop("ro.product.brand"),
            "device": await self._prop("ro.product.device"),
            "board": await self._prop("ro.product.board"),
            "hardware": await self._prop("ro.product.hardware"),
            "hardware_chipname": await self._prop("ro.hardware.chipname"),
            "soc_manufacturer": await self._prop("ro.soc.manufacturer"),
            "soc_model": await self._prop("ro.soc.model"),
            "serial": await self._prop("ro.boot.serialno"),
            "bootloader": await self._prop("ro.bootloader"),
            "radio": await self._prop("gsm.version.baseband"),
            "physical_ram": (
                await self._adb.shell("cat /proc/meminfo 2>/dev/null | head -1")
            ).strip(),
            "cpu_info": (await self._adb.shell("cat /proc/cpuinfo 2>/dev/null | head -20")).strip(),
            "screen_resolution": (await self._adb.shell("wm size 2>/dev/null")).strip(),
            "screen_density": (await self._adb.shell("wm density 2>/dev/null")).strip(),
        }

    async def _get_os_info(self) -> dict[str, Any]:
        return {
            "android_version": await self._prop("ro.build.version.release"),
            "sdk_level": await self._prop("ro.build.version.sdk"),
            "security_patch": await self._prop("ro.build.version.security_patch"),
            "build_id": await self._prop("ro.build.display.id"),
            "build_fingerprint": await self._prop("ro.build.fingerprint"),
            "build_type": await self._prop("ro.build.type"),
            "build_tags": await self._prop("ro.build.tags"),
            "build_date": await self._prop("ro.build.date"),
            "build_user": await self._prop("ro.build.user"),
            "build_host": await self._prop("ro.build.host"),
            "incremental": await self._prop("ro.build.version.incremental"),
            "preview_sdk": await self._prop("ro.build.version.preview_sdk"),
            "release_or_codename": await self._prop("ro.build.version.codename"),
            "is_release": await self._prop("ro.build.version.all_codelines"),
            "system_ota": await self._prop("ro.build.version.ota"),
            "treble_enabled": await self._prop("ro.treble.enabled"),
            "project_treble": await self._prop("ro.product.first_api_level"),
        }

    async def _get_kernel_info(self) -> dict[str, Any]:
        kernel = (await self._adb.shell("uname -a 2>/dev/null")).strip()
        kernel_release = (await self._adb.shell("uname -r 2>/dev/null")).strip()
        modules = (await self._adb.shell("lsmod 2>/dev/null | head -30")).strip()
        cmdline = (await self._adb.shell("cat /proc/cmdline 2>/dev/null")).strip()
        return {
            "full": kernel,
            "release": kernel_release,
            "loaded_modules": modules,
            "boot_command_line": cmdline,
        }

    async def _get_security_profile(self) -> dict[str, Any]:
        selinux = (await self._adb.shell("getenforce 2>/dev/null")).strip()
        selinux_context = (await self._adb.shell("id 2>/dev/null")).strip()
        verified_boot = await self._prop("ro.boot.verifiedbootstate")
        vbmeta = await self._prop("ro.boot.vbmeta.device_state")
        dm_verity = await self._adb.shell(
            "cat /proc/cmdline 2>/dev/null | tr ' ' '\n' | grep -i verity"
        )
        avb_version = await self._prop("ro.boot.avb_version")
        security_features = (
            await self._adb.shell(
                "cat /proc/cpuinfo 2>/dev/null | grep -i -E 'flag|feature' | head -5"
            )
        ).strip()
        return {
            "selinux_mode": selinux,
            "current_context": selinux_context,
            "verified_boot_state": verified_boot,
            "vbmeta_device_state": vbmeta,
            "dm_verity": dm_verity.strip() if dm_verity else "",
            "avb_version": avb_version,
            "cpu_security_features": security_features,
        }

    async def _get_crypto_info(self) -> dict[str, Any]:
        fstab = (
            await self._adb.shell("cat /vendor/etc/fstab.* 2>/dev/null || cat /fstab.* 2>/dev/null")
        ).strip()
        fbe = await self._prop("ro.crypto.state")
        cipher = await self._prop("ro.crypto.fs_crypto_suffix")
        vold = await self._prop("vold.decrypt")
        encryption_status = (await self._adb.shell("dumpsys vold 2>/dev/null | head -30")).strip()
        keymaster = (
            await self._adb.shell(
                "dumpsys android.hardware.security.keymint 2>/dev/null | head -20"
            )
        ).strip()
        gatekeeper = (
            await self._adb.shell("dumpsys android.hardware.gatekeeper 2>/dev/null | head -10")
        ).strip()
        return {
            "filesystem_encryption": fbe,
            "fs_crypto_suffix": cipher,
            "vold_decrypt_state": vold,
            "encryption_status_detail": encryption_status,
            "keymaster_info": keymaster,
            "gatekeeper_info": gatekeeper,
            "fstab": fstab[:500] if fstab else "",
        }

    async def _get_network_profile(self) -> dict[str, Any]:
        interfaces = (await self._adb.shell("ip addr show 2>/dev/null")).strip()
        wifi_info = (await self._adb.shell("dumpsys wifi 2>/dev/null | head -50")).strip()
        dns = (await self._adb.shell("cat /etc/resolv.conf 2>/dev/null")).strip()
        private_dns = (
            await self._adb.shell("settings get global private_dns_specifier 2>/dev/null")
        ).strip()
        vpn = (
            await self._adb.shell("dumpsys connectivity 2>/dev/null | grep -i vpn | head -5")
        ).strip()
        routing_table = (await self._adb.shell("ip route 2>/dev/null")).strip()
        arp = (await self._adb.shell("ip neigh 2>/dev/null | head -20")).strip()
        iptables = (await self._adb.shell("iptables -L -n 2>/dev/null | head -30")).strip()
        return {
            "interfaces": interfaces,
            "wifi_info": wifi_info,
            "dns_config": dns,
            "private_dns": private_dns,
            "vpn_status": vpn,
            "routing_table": routing_table,
            "arp_table": arp,
            "firewall_rules": iptables,
        }

    async def _get_user_accounts(self) -> dict[str, Any]:
        users = (await self._adb.shell("pm list users 2>/dev/null")).strip()
        who = (await self._adb.shell("who 2>/dev/null")).strip()
        last_login = (await self._adb.shell("last -10 2>/dev/null")).strip()
        return {
            "android_users": users,
            "logged_in_users": who,
            "recent_logins": last_login,
        }

    async def _get_sync_accounts(self) -> dict[str, Any]:
        accounts = (await self._adb.shell("dumpsys account 2>/dev/null | head -50")).strip()
        return {"accounts_dump": accounts}

    async def _get_storage_detail(self) -> dict[str, Any]:
        df = (await self._adb.shell("df -h 2>/dev/null")).strip()
        emulated = (await self._adb.shell("ls -la /storage/emulated/ 2>/dev/null")).strip()
        sdcard = (await self._adb.shell("ls -la /sdcard/ 2>/dev/null | head -20")).strip()
        adoptable = (await self._adb.shell("sm list-volumes all 2>/dev/null")).strip()
        return {
            "disk_usage": df,
            "emulated_storage": emulated,
            "sdcard_contents": sdcard,
            "volumes": adoptable,
        }

    async def _get_battery_detail(self) -> dict[str, Any]:
        battery = (await self._adb.shell("dumpsys battery 2>/dev/null")).strip()
        battery_stats = (
            await self._adb.shell("dumpsys batterystats 2>/dev/null | head -50")
        ).strip()
        charging = await self._prop("charger.online")
        return {
            "battery_info": battery,
            "battery_stats": battery_stats,
            "charger_online": charging,
        }

    async def _get_display_info(self) -> dict[str, Any]:
        display = (await self._adb.shell("dumpsys display 2>/dev/null | head -40")).strip()
        brightness = (
            await self._adb.shell("settings get system screen_brightness 2>/dev/null")
        ).strip()
        auto_rotate = (
            await self._adb.shell("settings get system accelerometer_rotation 2>/dev/null")
        ).strip()
        return {
            "display_info": display,
            "brightness": brightness,
            "auto_rotate": auto_rotate,
        }

    async def _get_telephony_info(self) -> dict[str, Any]:
        sim_state = await self._prop("gsm.sim.state")
        operator = await self._prop("gsm.operator.alpha")
        network_type = await self._prop("gsm.network.type")
        imei_info = (await self._adb.shell("service call iphonesubinfo 1 2>/dev/null")).strip()
        carrier = await self._prop("gsm.sim.operator.alpha")
        phone_number = await self._prop("gsm.sim.operator.numeric")
        return {
            "sim_state": sim_state,
            "operator": operator,
            "network_type": network_type,
            "carrier": carrier,
            "operator_code": phone_number,
            "imei_raw": imei_info[:200] if imei_info else "",
        }

    async def _get_usb_info(self) -> dict[str, Any]:
        usb = (await self._adb.shell("lsusb 2>/dev/null")).strip()
        usb_config = await self._prop("sys.usb.config")
        usb_state = await self._prop("sys.usb.state")
        adb_enabled = await self._prop("persist.sys.usb.config")
        return {
            "usb_devices": usb,
            "usb_config": usb_config,
            "usb_state": usb_state,
            "persist_usb_config": adb_enabled,
        }

    async def _get_bluetooth_info(self) -> dict[str, Any]:
        bt = (await self._adb.shell("dumpsys bluetooth_manager 2>/dev/null | head -30")).strip()
        return {"bluetooth_dump": bt}

    async def _get_location_providers(self) -> dict[str, Any]:
        providers = (
            await self._adb.shell("settings get secure location_providers_allowed 2>/dev/null")
        ).strip()
        location_mode = (
            await self._adb.shell("settings get secure location_mode 2>/dev/null")
        ).strip()
        return {
            "providers": providers,
            "location_mode": location_mode,
        }

    async def _get_accessibility_detail(self) -> dict[str, Any]:
        enabled = (
            await self._adb.shell("settings get secure enabled_accessibility_services 2>/dev/null")
        ).strip()
        installed = (await self._adb.shell("dumpsys accessibility 2>/dev/null | head -30")).strip()
        return {
            "enabled_services": enabled,
            "accessibility_dump": installed,
        }

    async def _get_device_admins(self) -> dict[str, Any]:
        admins = (await self._adb.shell("dumpsys device_policy 2>/dev/null | head -30")).strip()
        return {"device_admins": admins}

    async def _get_input_methods(self) -> dict[str, Any]:
        ime = (
            await self._adb.shell("settings get secure default_input_method 2>/dev/null")
        ).strip()
        enabled = (
            await self._adb.shell("settings get secure enabled_input_methods 2>/dev/null")
        ).strip()
        return {
            "default_ime": ime,
            "enabled_imes": enabled,
        }

    async def _get_launcher_apps(self) -> dict[str, Any]:
        launcher = (
            await self._adb.shell(
                "cmd package resolve-activity -a android.intent.action.MAIN -c android.intent.category.LAUNCHER 2>/dev/null | head -5"
            )
        ).strip()
        default_launcher = (
            await self._adb.shell("cmd shortcut get-default-launcher 2>/dev/null")
        ).strip()
        return {
            "default_launcher_activity": launcher,
            "default_launcher": default_launcher,
        }

    async def _get_package_summary(self) -> dict[str, Any]:
        third_party = (await self._adb.shell("pm list packages -3 2>/dev/null")).strip()
        system = (await self._adb.shell("pm list packages -s 2>/dev/null")).strip()
        disabled = (await self._adb.shell("pm list packages -d 2>/dev/null")).strip()
        (await self._adb.shell("pm list packages -e 2>/dev/null")).strip()

        tp_count = len(third_party.splitlines()) if third_party else 0
        sys_count = len(system.splitlines()) if system else 0
        dis_count = len(disabled.splitlines()) if disabled else 0

        suspicious_keywords = [
            "root",
            "hack",
            "exploit",
            "keylog",
            "spy",
            "track",
            "remote",
            "rat",
            "backdoor",
            "trojan",
        ]
        flagged = []
        for line in (third_party or "").splitlines():
            pkg = line.replace("package:", "").strip().lower()
            if any(kw in pkg for kw in suspicious_keywords):
                flagged.append(pkg)

        return {
            "third_party_count": tp_count,
            "system_count": sys_count,
            "disabled_count": dis_count,
            "third_party_list": third_party[:3000] if third_party else "",
            "flagged_package_names": flagged,
        }

    async def _get_running_services(self) -> dict[str, Any]:
        services = (
            await self._adb.shell(
                "dumpsys activity services 2>/dev/null | grep -E 'ServiceRecord|app=' | head -40"
            )
        ).strip()
        return {"running_services": services}

    async def _get_process_snapshot(self) -> dict[str, Any]:
        ps = (await self._adb.shell("ps -A -o PID,PPID,USER,VSZ,RSS,NAME 2>/dev/null")).strip()
        proc_count = len(ps.splitlines()) - 1 if ps else 0
        return {
            "total_processes": proc_count,
            "process_list": ps[:3000] if ps else "",
        }

    async def _get_mount_info(self) -> dict[str, Any]:
        mounts = (await self._adb.shell("cat /proc/mounts 2>/dev/null")).strip()
        return {"mounts": mounts[:3000] if mounts else ""}

    async def _get_selinux_status(self) -> dict[str, Any]:
        mode = (await self._adb.shell("getenforce 2>/dev/null")).strip()
        policy = (
            await self._adb.shell(
                "cat /sys/fs/selinux/policy 2>/dev/null | head -c 100 | xxd | head -3"
            )
        ).strip()
        context = (await self._adb.shell("cat /proc/1/attr/current 2>/dev/null")).strip()
        return {
            "mode": mode,
            "init_context": context,
            "policy_preview": policy,
        }

    async def _get_all_properties(self) -> dict[str, str]:
        raw = await self._adb.shell("getprop 2>/dev/null")
        props: dict[str, str] = {}
        for line in raw.strip().splitlines():
            if line.startswith("["):
                parts = line.split("]: ", 1)
                if len(parts) == 2:
                    key = parts[0].strip("[]")
                    val = parts[1].strip("[]")
                    props[key] = val
        return props

    async def _prop(self, key: str) -> str:
        return (await self._adb.shell(f"getprop {key} 2>/dev/null")).strip()

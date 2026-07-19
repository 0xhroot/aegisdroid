"""APK analysis adapter using androguard and custom analysis."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import zipfile
from typing import Any

from aegisdroid.core.domain import (
    AppInfo,
    CertificateInfo,
    ComponentInfo,
    ComponentType,
    Hash,
    NativeLibrary,
    PermissionInfo,
)
from aegisdroid.core.interfaces import APKAnalysisPort

logger = logging.getLogger(__name__)

KNOWN_TRACKERS: dict[str, list[str]] = {
    "Google Analytics": ["com/google/android/gms/analytics", "com/google/firebase/analytics"],
    "Google AdMob": ["com/google/android/gms/ads", "com/google/ads"],
    "Facebook Analytics": ["com/facebook/appevents", "com/facebook/analytics"],
    "Facebook Ads": ["com/facebook/ads"],
    "Flurry": ["com/flurry/android"],
    "Mixpanel": ["com/mixpanel"],
    "Amplitude": ["com/amplitude"],
    "Segment": ["com/segment"],
    "AppsFlyer": ["com/appsflyer"],
    "Adjust": ["com/adjust"],
    "Branch": ["com/branch"],
    "OneSignal": ["com/onesignal"],
    "Firebase Messaging": ["com/google/firebase/messaging"],
    "Branch Metrics": ["io/branch"],
    "Leanplum": ["com/leanplum"],
    "Localytics": ["com/localytics"],
    "Crittercism": ["com/crittercism"],
    "Crashlytics": ["com/crashlytics"],
    "Matomo": ["org/matomo"],
    "Tracking": ["com/tune", "com/kochava"],
    "Microsoft AppCenter": ["com/microsoft/appcenter"],
}

SUSPICIOUS_URL_PATTERNS = [
    r"https?://[^\s]+\.(tk|ml|ga|cf|gq|buzz|xyz|top|club|work|click|link|download)/",
    r"https?://[^\s]+/\b(c2|command|control|payload|exploit|payload|shell|backdoor)\b",
    r"https?://\d+\.\d+\.\d+\.\d+",
    r"ftp://",
]

SUSPICIOUS_IP_PATTERN = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

DYNAMIC_CODE_INDICATORS = [
    "dalvik.system.DexClassLoader",
    "dalvik.system.PathClassLoader",
    "dalvik.system.InMemoryDexClassLoader",
    "java.lang.ClassLoader",
    "java.lang.reflect.Method",
    "java.lang.reflect.Field",
    "java.lang.reflect.Constructor",
    "dalvik.system.DexFile",
    r"android.content.res.Resources\$Theme",
]

REFLECTION_INDICATORS = [
    "java.lang.reflect.Method.invoke",
    "java.lang.Class.forName",
    "java.lang.Class.getMethod",
    "java.lang.Class.getDeclaredMethod",
]


class APKAnalyzer(APKAnalysisPort):
    """APK static analysis adapter."""

    async def analyze(self, apk_path: str) -> AppInfo:
        return await asyncio.to_thread(self._analyze_sync, apk_path)

    def _analyze_sync(self, apk_path: str) -> AppInfo:
        try:
            from androguard.misc import AnalyzeAPK
        except ImportError:
            logger.warning("androguard not available, using basic analysis")
            return self._basic_analysis(apk_path)

        try:
            a, d, _dx = AnalyzeAPK(apk_path)
        except Exception as e:
            logger.exception("androguard failed to analyze %s: %s", apk_path, e)
            return self._basic_analysis(apk_path)

        permissions = [
            PermissionInfo(
                name=p,
                protection_level="dangerous" if p in PermissionInfo.RISKY_PERMISSIONS else "normal",
                is_dangerous=p in PermissionInfo.RISKY_PERMISSIONS,
            )
            for p in a.get_permissions()
        ]

        components = self._extract_components(a)

        cert = None
        try:
            certs = a.get_certificates_v2()
            if certs:
                c = certs[0]
                cert = CertificateInfo(
                    subject=str(c.subject.human_friendly),
                    issuer=str(c.issuer.human_friendly),
                    sha256=hashlib.sha256(c.public_bytes).hexdigest()
                    if hasattr(c, "public_bytes")
                    else "",
                    is_debug="debug" in str(c.subject).lower(),
                )
        except Exception:
            try:
                cert_info = a.get_signature_names()
                if cert_info:
                    cert = CertificateInfo(
                        subject=str(cert_info),
                        is_debug="debug" in str(cert_info).lower(),
                    )
            except Exception:
                pass

        native_libs = []
        for lib in a.get_libraries():
            native_libs.append(NativeLibrary(name=lib, arch="universal"))

        apk_hash = Hash.from_file(apk_path)

        has_dynamic = False
        has_reflection = False
        for d_analysis in d:
            for string in d_analysis.get_strings():
                if string in DYNAMIC_CODE_INDICATORS:
                    has_dynamic = True
                if string in REFLECTION_INDICATORS:
                    has_reflection = True

        a.get_android_manifest()
        package = a.get_package()
        trackers = self._detect_trackers(a)

        embedded_urls = set()
        embedded_ips = set()
        for d_analysis in d:
            for string in d_analysis.get_strings():
                for pattern in SUSPICIOUS_URL_PATTERNS:
                    matches = re.findall(pattern, string)
                    embedded_urls.update(matches)
                ip_matches = re.findall(SUSPICIOUS_IP_PATTERN, string)
                for ip in ip_matches:
                    if not ip.startswith(("0.", "127.", "255.")):
                        embedded_ips.add(ip)

        return AppInfo(
            package_name=package,
            version_name=a.get_androidversion_name() or "",
            version_code=int(a.get_androidversion_code() or 0),
            target_sdk=int(a.get_target_sdk_version() or 0),
            min_sdk=int(a.get_min_sdk_version() or 0),
            is_debuggable=a.get_attribute_value("application", "debuggable") == "true",
            is_backup_allowed=a.get_attribute_value("application", "allowBackup") != "false",
            has_native_code=len(native_libs) > 0,
            has_native_libs=len(native_libs) > 0,
            has_dynamic_code=has_dynamic or has_reflection,
            permissions=permissions,
            components=components,
            native_libraries=native_libs,
            certificate=cert,
            apk_path=apk_path,
            apk_hash=apk_hash,
            trackers=trackers,
            embedded_urls=list(embedded_urls),
            embedded_ips=list(embedded_ips),
            features=[],
        )

    def _extract_components(self, a: Any) -> list[ComponentInfo]:
        components = []
        manifest = a.get_android_manifest()

        for tag, comp_type in [
            ("activity", ComponentType.ACTIVITY),
            ("service", ComponentType.SERVICE),
            ("receiver", ComponentType.RECEIVER),
            ("provider", ComponentType.PROVIDER),
        ]:
            for elem in manifest.getElementsByTagName(tag):
                name = elem.getAttribute("android:name")
                exported = elem.getAttribute("android:exported")
                enabled = elem.getAttribute("android:enabled")
                permission = elem.getAttribute("android:permission")

                is_exported = exported == "true"
                has_intent_filter = len(elem.getElementsByTagName("intent-filter")) > 0

                if not exported and has_intent_filter:
                    is_exported = True

                components.append(
                    ComponentInfo(
                        name=name,
                        component_type=comp_type,
                        exported=is_exported,
                        enabled=enabled != "false",
                        permission=permission,
                        has_intent_filter=has_intent_filter,
                        is_protected=bool(permission),
                    )
                )

        return components

    def _detect_trackers(self, a: Any) -> list[str]:
        found = []
        all_code = " ".join(
            a.get_permissions()
            + a.get_activities()
            + a.get_services()
            + a.get_receivers()
            + a.get_providers()
        )
        for tracker_name, patterns in KNOWN_TRACKERS.items():
            for pattern in patterns:
                if pattern in all_code:
                    found.append(tracker_name)
                    break
        return found

    def _basic_analysis(self, apk_path: str) -> AppInfo:
        """Fallback analysis without androguard."""
        app_info = AppInfo(apk_path=apk_path)
        app_info.apk_hash = Hash.from_file(apk_path)

        try:
            with zipfile.ZipFile(apk_path) as zf:
                names = zf.namelist()
                app_info.has_native_libs = any(n.startswith("lib/") for n in names)
                app_info.has_dynamic_code = any(
                    "classes" in n and n.endswith(".dex") for n in names
                )
        except Exception as e:
            logger.exception("Basic APK analysis failed: %s", e)

        return app_info

    async def extract_manifest(self, apk_path: str) -> dict[str, Any]:
        try:
            from androguard.misc import AnalyzeAPK

            a, _, _ = AnalyzeAPK(apk_path)
            manifest = a.get_android_manifest()
            return {"xml": manifest.toxml() if manifest else ""}
        except Exception:
            return {"xml": ""}

    async def get_permissions(self, apk_path: str) -> list[PermissionInfo]:
        app = await self.analyze(apk_path)
        return app.permissions

    async def get_components(self, apk_path: str) -> list[ComponentInfo]:
        app = await self.analyze(apk_path)
        return app.components

    async def get_certificate(self, apk_path: str) -> CertificateInfo | None:
        app = await self.analyze(apk_path)
        return app.certificate

    async def get_native_libs(self, apk_path: str) -> list[str]:
        libs = []
        try:
            with zipfile.ZipFile(apk_path) as zf:
                for name in zf.namelist():
                    if name.startswith("lib/") and name.endswith(".so"):
                        libs.append(name)
        except Exception:
            pass
        return libs

    async def find_strings(self, apk_path: str, pattern: str) -> list[str]:
        matches: list[str] = []
        try:
            with zipfile.ZipFile(apk_path) as zf:
                for name in zf.namelist():
                    if name.endswith((".dex", ".so", ".xml")):
                        data = zf.read(name)
                        found = re.findall(pattern.encode(), data)
                        matches.extend(f.decode("utf-8", errors="replace") for f in found)
        except Exception:
            pass
        return matches

    async def analyze_dex(self, apk_path: str) -> dict[str, Any]:
        result: dict[str, Any] = {"classes": [], "methods": [], "strings": []}
        try:
            with zipfile.ZipFile(apk_path) as zf:
                dex_files = [n for n in zf.namelist() if n.endswith(".dex")]
                result["dex_count"] = len(dex_files)
                for dex_name in dex_files:
                    data = zf.read(dex_name)
                    result["strings"].extend(
                        s.decode("utf-8", errors="replace")
                        for s in re.findall(rb"[\x20-\x7e]{6,}", data)
                    )
        except Exception:
            pass
        return result

    async def detect_trackers(self, apk_path: str) -> list[str]:
        app = await self.analyze(apk_path)
        return app.trackers

    async def generate_sbom(self, apk_path: str) -> dict[str, Any]:
        app = await self.analyze(apk_path)
        return {
            "package": app.package_name,
            "version": app.version_name,
            "permissions": [p.name for p in app.permissions],
            "components": [c.name for c in app.components],
            "native_libraries": [l.name for l in app.native_libraries],
            "trackers": app.trackers,
            "certificate": {
                "subject": app.certificate.subject if app.certificate else "",
                "issuer": app.certificate.issuer if app.certificate else "",
            }
            if app.certificate
            else None,
        }

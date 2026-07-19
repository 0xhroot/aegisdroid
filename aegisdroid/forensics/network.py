"""Network intelligence analysis."""

from __future__ import annotations

import logging
import re
from typing import Any

from aegisdroid.core.domain import (
    Evidence,
    EvidenceType,
    Finding,
    NetworkConnection,
    Severity,
    ThreatCategory,
)

logger = logging.getLogger(__name__)


class NetworkAnalyzer:
    """Android network traffic analysis and intelligence."""

    SUSPICIOUS_PORTS = {4444, 5555, 6666, 7777, 8888, 9999, 1234, 31337, 1337}
    CRYPTO_MINING_PORTS = {3333, 4444, 5555, 7777, 8888, 9999, 14433, 14444, 45560}

    def __init__(self, adb: Any = None) -> None:
        self._adb = adb

    async def analyze_connections(self) -> list[NetworkConnection]:
        if not self._adb:
            return []

        connections: list[NetworkConnection] = []

        tcp_out = await self._adb.shell("cat /proc/net/tcp 2>/dev/null")
        tcp6_out = await self._adb.shell("cat /proc/net/tcp6 2>/dev/null")

        for line in tcp_out.strip().splitlines()[1:]:
            conn = self._parse_tcp_line(line)
            if conn:
                connections.append(conn)

        for line in tcp6_out.strip().splitlines()[1:]:
            conn = self._parse_tcp6_line(line)
            if conn:
                connections.append(conn)

        return connections

    def _parse_tcp_line(self, line: str) -> NetworkConnection | None:
        parts = line.split()
        if len(parts) < 10:
            return None

        try:
            local = parts[1]
            remote = parts[2]
            state = parts[3]

            if state != "01":  # ESTABLISHED
                return None

            _local_ip, _local_port = self._decode_addr(local)
            remote_ip, remote_port = self._decode_addr(remote)

            if remote_ip in {"0.0.0.0", "127.0.0.1"}:
                return None

            suspicious = remote_port in self.SUSPICIOUS_PORTS

            return NetworkConnection(
                domain="",
                ip=remote_ip,
                port=remote_port,
                protocol="tcp",
                is_encrypted=remote_port in (443, 8443),
                suspicious=suspicious,
                reason=f"Suspicious port {remote_port}" if suspicious else "",
            )
        except (ValueError, IndexError):
            return None

    def _parse_tcp6_line(self, line: str) -> NetworkConnection | None:
        parts = line.split()
        if len(parts) < 10:
            return None

        try:
            remote = parts[2]
            state = parts[3]

            if state != "01":
                return None

            remote_ip, remote_port = self._decode_addr6(remote)

            if remote_ip in {"::", "::1"}:
                return None

            suspicious = remote_port in self.SUSPICIOUS_PORTS

            return NetworkConnection(
                domain="",
                ip=remote_ip,
                port=remote_port,
                protocol="tcp6",
                is_encrypted=remote_port in (443, 8443),
                suspicious=suspicious,
                reason=f"Suspicious port {remote_port}" if suspicious else "",
            )
        except (ValueError, IndexError):
            return None

    def _decode_addr(self, hex_addr: str) -> tuple[str, int]:
        ip_hex, port_hex = hex_addr.split(":")
        port = int(port_hex, 16)
        ip_int = int(ip_hex, 16)
        ip = f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
        return ip, port

    def _decode_addr6(self, hex_addr: str) -> tuple[str, int]:
        parts = hex_addr.split(":")
        if len(parts) < 5:
            return "::", 0
        port = int(parts[0], 16)
        ip_parts = []
        for p in parts[1:5]:
            ip_parts.append(f"{int(p[0:4], 16):04x}")
        ip = ":".join(ip_parts)
        return ip, port

    async def analyze_dns(self) -> list[dict[str, Any]]:
        if not self._adb:
            return []

        results = []
        out = await self._adb.shell("cat /etc/resolv.conf 2>/dev/null")
        for line in out.strip().splitlines():
            if "nameserver" in line:
                parts = line.split()
                if len(parts) >= 2:
                    results.append({"type": "nameserver", "address": parts[1]})

        priv_dns = await self._adb.shell("settings get global private_dns_specifier 2>/dev/null")
        if priv_dns.strip() and priv_dns.strip() != "null":
            results.append(
                {
                    "type": "private_dns",
                    "specifier": priv_dns.strip(),
                }
            )

        dns_queries = await self._adb.shell("logcat -d -b main -t 200 | grep -i dns 2>/dev/null")
        if dns_queries.strip():
            for line in dns_queries.strip().splitlines()[:20]:
                results.append({"type": "dns_log", "entry": line.strip()})

        return results

    async def analyze_vpn(self) -> dict[str, Any]:
        if not self._adb:
            return {}

        result: dict[str, Any] = {}

        vpn_out = await self._adb.shell(
            "dumpsys connectivity 2>/dev/null | grep -A5 'VPN' | head -20"
        )
        result["vpn_status"] = vpn_out.strip() if vpn_out else "unknown"

        tun_check = await self._adb.shell("ip link show tun0 2>/dev/null")
        result["tun0_active"] = bool(tun_check.strip() and "tun0" in tun_check)

        proxy_host = await self._adb.shell("settings get global http_proxy 2>/dev/null")
        result["http_proxy"] = proxy_host.strip() if proxy_host else "none"

        return result

    async def check_domain_reputation(self, domain: str) -> float:
        suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".club"}
        score = 0.5

        for tld in suspicious_tlds:
            if domain.endswith(tld):
                score -= 0.3
                break

        if len(domain.split(".")) > 4:
            score -= 0.1

        ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        if ip_pattern.match(domain):
            score -= 0.2

        return max(0.0, min(1.0, score))

    async def check_ip_reputation(self, ip: str) -> float:
        private_ranges = [
            ("10.0.0.0", "10.255.255.255"),
            ("172.16.0.0", "172.31.255.255"),
            ("192.168.0.0", "192.168.255.255"),
        ]
        for start, end in private_ranges:
            if start <= ip <= end:
                return 0.8

        if ip.startswith("127."):
            return 0.9

        return 0.5

    async def build_connection_graph(self) -> dict[str, Any]:
        connections = await self.analyze_connections()
        graph: dict[str, Any] = {"nodes": [], "edges": []}

        seen_ips = set()
        for conn in connections:
            if conn.ip not in seen_ips:
                graph["nodes"].append(
                    {
                        "id": conn.ip,
                        "type": "ip",
                        "port": conn.port,
                        "suspicious": conn.suspicious,
                    }
                )
                seen_ips.add(conn.ip)

            graph["edges"].append(
                {
                    "source": "device",
                    "target": conn.ip,
                    "port": conn.port,
                    "encrypted": conn.is_encrypted,
                }
            )

        return graph

    async def detect_network_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        if not self._adb:
            return findings

        connections = await self.analyze_connections()
        suspicious = [c for c in connections if c.suspicious]

        if suspicious:
            findings.append(
                Finding(
                    category=ThreatCategory.NETWORK_ANOMALY,
                    severity=Severity.HIGH,
                    title=f"Suspicious network connections ({len(suspicious)})",
                    description=f"Device has {len(suspicious)} connections to suspicious ports.",
                    evidence=[
                        Evidence(
                            type=EvidenceType.NETWORK,
                            source="network_analysis",
                            description=f"Suspicious connection: {c.ip}:{c.port} - {c.reason}",
                            confidence=0.8,
                        )
                        for c in suspicious[:10]
                    ],
                    confidence=0.75,
                    mitigation="Investigate suspicious network connections for C2 or exfiltration.",
                )
            )

        vpn = await self.analyze_vpn()
        if vpn.get("tun0_active"):
            findings.append(
                Finding(
                    category=ThreatCategory.NETWORK_ANOMALY,
                    severity=Severity.INFO,
                    title="VPN connection active",
                    description="Device has an active VPN connection (tun0 interface).",
                    evidence=[
                        Evidence(
                            type=EvidenceType.NETWORK,
                            source="network_analysis",
                            description="Active tun0 interface detected",
                            confidence=0.9,
                        )
                    ],
                    confidence=0.9,
                    mitigation="VPN usage is common but may be used to hide malicious traffic.",
                )
            )

        dns = await self.analyze_dns()
        priv_dns = [d for d in dns if d.get("type") == "private_dns"]
        if priv_dns:
            findings.append(
                Finding(
                    category=ThreatCategory.NETWORK_ANOMALY,
                    severity=Severity.INFO,
                    title="Private DNS configured",
                    description=f"Private DNS specifier: {priv_dns[0].get('specifier', 'unknown')}",
                    evidence=[
                        Evidence(
                            type=EvidenceType.NETWORK,
                            source="dns_analysis",
                            description=f"Private DNS: {d.get('specifier', '')}",
                            confidence=0.9,
                        )
                        for d in priv_dns
                    ],
                    confidence=0.85,
                    mitigation="Private DNS can encrypt DNS but also hide malicious queries.",
                )
            )

        return findings

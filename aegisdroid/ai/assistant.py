"""AI assistant integration for analysis and reporting."""

from __future__ import annotations

import json
import logging
from typing import Any

from aegisdroid.core.config import AIConfig
from aegisdroid.core.domain import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)


class AIAssistant:
    """AI-powered analysis assistant using Ollama or OpenAI."""

    def __init__(self, config: AIConfig | None = None) -> None:
        self._config = config or AIConfig()

    async def explain_finding(self, finding: Finding) -> str:
        if not self._config.enabled:
            return self._explain_finding_local(finding)

        prompt = (
            f"Explain this Android security finding in clear, professional language "
            f"for a security analyst:\n\n"
            f"Category: {finding.category.value}\n"
            f"Severity: {finding.severity.value}\n"
            f"Title: {finding.title}\n"
            f"Description: {finding.description}\n"
            f"Evidence: {', '.join(e.description for e in finding.evidence)}\n"
            f"Confidence: {finding.confidence:.0%}\n"
        )
        return await self._query(prompt)

    async def generate_report(self, scan_result: ScanResult) -> str:
        findings_summary = "\n".join(
            f"- [{f.severity.value.upper()}] {f.title}: {f.description[:100]}"
            for f in scan_result.findings
        )

        prompt = (
            f"Generate a professional incident report for this Android security scan.\n\n"
            f"Device: {scan_result.device_serial}\n"
            f"Package: {scan_result.package_name}\n"
            f"Threat Score: {scan_result.threat_confidence_score:.0%}\n"
            f"Total Findings: {len(scan_result.findings)}\n\n"
            f"Findings:\n{findings_summary}\n\n"
            f"Include: Executive Summary, Key Findings, Risk Assessment, "
            f"Recommended Actions.\n"
        )
        return await self._query(prompt)

    async def suggest_remediation(self, findings: list[Finding]) -> list[str]:
        if not self._config.enabled:
            return [f.mitigation for f in findings if f.mitigation]

        prompt = "Suggest specific remediation steps for these Android security findings:\n\n"
        for f in findings:
            prompt += f"- [{f.severity.value}] {f.title}: {f.description[:80]}\n"

        prompt += "\nProvide actionable, specific remediation steps."
        result = await self._query(prompt)
        return [line.strip() for line in result.split("\n") if line.strip()]

    async def natural_language_query(self, query: str, context: dict[str, Any]) -> str:
        prompt = (
            f"Based on this Android device analysis context:\n"
            f"{json.dumps(context, indent=2, default=str)[:2000]}\n\n"
            f"Answer this question: {query}\n"
        )
        return await self._query(prompt)

    async def _query(self, prompt: str) -> str:
        if self._config.provider == "ollama":
            return await self._query_ollama(prompt)
        if self._config.provider == "openai":
            return await self._query_openai(prompt)
        return "AI provider not configured."

    async def _query_ollama(self, prompt: str) -> str:
        try:
            import httpx

            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(
                    f"{self._config.ollama_host}/api/generate",
                    json={
                        "model": self._config.model,
                        "prompt": prompt,
                        "stream": False,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("response", "No response")
                return f"Ollama error: {resp.status_code}"
        except Exception as e:
            logger.exception("Ollama query failed: %s", e)
            return f"AI unavailable: {e}"

    async def _query_openai(self, prompt: str) -> str:
        try:
            import httpx

            async with httpx.AsyncClient(timeout=120) as client:
                resp = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self._config.openai_api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self._config.openai_model,
                        "messages": [
                            {
                                "role": "system",
                                "content": "You are an expert Android security analyst and malware researcher. Provide clear, evidence-based analysis.",
                            },
                            {"role": "user", "content": prompt},
                        ],
                        "max_tokens": self._config.max_tokens,
                        "temperature": self._config.temperature,
                    },
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data["choices"][0]["message"]["content"]
                return f"OpenAI error: {resp.status_code}"
        except Exception as e:
            logger.exception("OpenAI query failed: %s", e)
            return f"AI unavailable: {e}"

    def _explain_finding_local(self, finding: Finding) -> str:
        explanations = {
            Severity.CRITICAL: "This is a critical security finding that requires immediate attention.",
            Severity.HIGH: "This is a high-severity finding that should be investigated promptly.",
            Severity.MEDIUM: "This is a medium-severity finding that warrants review.",
            Severity.LOW: "This is a low-severity informational finding.",
            Severity.INFO: "This is an informational observation.",
        }

        base = explanations.get(finding.severity, "This finding requires review.")

        lines = [
            f"**{finding.title}**",
            "",
            base,
            "",
            f"**Category:** {finding.category.value.replace('_', ' ').title()}",
            f"**Confidence:** {finding.confidence:.0%}",
            "",
            finding.description,
            "",
        ]

        if finding.evidence:
            lines.append("**Evidence:**")
            for e in finding.evidence:
                lines.append(f"  - {e.description}")

        if finding.mitigation:
            lines.append("")
            lines.append(f"**Mitigation:** {finding.mitigation}")

        return "\n".join(lines)

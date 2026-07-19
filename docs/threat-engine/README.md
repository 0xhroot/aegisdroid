# Threat Engine

## Overview

AegisDroid uses an evidence-based correlation model for threat detection.

## How It Works

1. **Evidence Collection** — Each analysis engine produces `Evidence` objects
2. **Finding Creation** — Evidence is grouped into `Finding` objects with confidence scores
3. **Correlation** — The correlation engine cross-references findings for patterns
4. **Scoring** — Threat confidence score is calculated from all findings

## Confidence Scoring

Each finding's confidence is derived from:

| Factor | Weight | Description |
|--------|--------|-------------|
| Evidence count | 30% | More independent evidence = higher confidence |
| Evidence type | 20% | Static analysis > behavioral > heuristic |
| Category risk | 25% | Root/backdoor categories carry inherent risk |
| Correlation | 25% | Related findings amplify each other |

## Severity Mapping

| Severity | Score Range | Response |
|----------|-------------|----------|
| CRITICAL | 90–100% | Immediate action |
| HIGH | 70–89% | Prompt investigation |
| MEDIUM | 40–69% | Review recommended |
| LOW | 20–39% | Minor observations |
| INFO | 0–19% | Informational |

## Correlation Patterns

| Pattern | Correlation | Result |
|---------|-------------|--------|
| Accessibility + Overlay | Overlay attack | HIGH |
| Dynamic code + Network | Data exfiltration | HIGH |
| Root + Frida + Xposed | Full compromise | CRITICAL |
| Permissions + Exports | Overprivileged app | HIGH |
| Accessibility + Dynamic | Banking trojan | HIGH |

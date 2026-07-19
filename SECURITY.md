# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | ✅ Active support  |
| < 1.0   | ❌ End of life     |

## Reporting a Vulnerability

The AegisDroid team takes security seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@aegisdroid.dev**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

### Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix development | Depends on severity |
| Public disclosure | After fix is released |

### What to Expect

- We will acknowledge receipt within 48 hours
- We will provide an initial assessment within 5 business days
- We will work with you to understand and validate the issue
- We will develop and test a fix
- We will credit you in the release notes (unless you prefer anonymity)

## Security Model

### Design Principles

1. **Read-Only Analysis** — AegisDroid never modifies the target device
2. **Zero Telemetry** — All analysis runs locally; no data leaves the device
3. **Evidence-Based** — Every finding includes evidence and confidence scores
4. **Local Processing** — No cloud dependency for core functionality
5. **Minimal Attack Surface** — CLI-only; no network services exposed

### Threat Model

AegisDroid operates under these assumptions:

| Assumption | Implication |
|------------|-------------|
| Physical or ADB access to target | Cannot analyze devices without access |
| Trusted analysis host | The host running AegisDroid is not compromised |
| Standard user privileges | No root required on the analysis host |
| ADB debugging enabled | Target device must have USB debugging on |

### Known Limitations

- Cannot perform memory forensics without root on target
- Cannot access encrypted app data without root
- YARA rules may produce false positives with heavy obfuscation
- Root detection may flag legitimate custom ROM configurations
- No network-based analysis (by design — privacy first)

### Privacy Statement

- **No telemetry**: AegisDroid collects and sends zero analytics data
- **No cloud dependency**: Core functionality works entirely offline
- **No phone home**: The tool never contacts external servers
- **Local database**: All scan data stored locally in SQLite
- **AI opt-in**: When enabled, AI analysis runs locally (Ollama) or requires explicit opt-in (OpenAI)
- **Open source**: Full source code is available for audit

### Dependency Security

- Dependencies are pinned with minimum versions
- CI includes dependency review workflows
- Dependabot monitors for known vulnerabilities
- Regular security audits of transitive dependencies

## Best Practices

When using AegisDroid:

1. **Keep updated**: Use the latest version for security fixes
2. **Verify downloads**: Check SHA256 checksums for release artifacts
3. **Secure your host**: The analysis host should be trusted and updated
4. **Protect scan data**: SQLite databases may contain sensitive device information
5. **Review findings**: Always verify findings manually before taking action

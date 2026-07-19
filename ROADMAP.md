# Roadmap

AegisDroid's development roadmap — what's planned, in progress, and completed.

## Legend

- ✅ Completed
- 🔄 In Progress
- 📋 Planned
- 💭 Under Consideration

---

## v1.0.0 — Current Release ✅

### Core

- ✅ Interactive numbered menu (20 options)
- ✅ Quick / Full / Deep / Target scan types
- ✅ Hexagonal Architecture + DDD + Event Bus
- ✅ Async SQLite persistence
- ✅ YAML configuration with defaults

### Detection Engines

- ✅ Root detection (Magisk, KernelSU, APatch, BusyBox, OverlayFS)
- ✅ Hooking framework detection (Frida, Xposed, LSPosed, Riru)
- ✅ Boot chain analysis (AVB, DM-Verity, Verified Boot)
- ✅ Malware scanner (known malware DB, permission combos)
- ✅ Backdoor detector (persistence, hidden dirs, bind mounts)
- ✅ Crypto miner detection

### Forensics

- ✅ Filesystem forensics (root files, SUID, executables, scripts)
- ✅ Network analysis (TCP, DNS, VPN, reputation)
- ✅ Device profiling (26-section comprehensive profile)
- ✅ Timeline reconstruction

### Analysis

- ✅ APK analysis (androguard-based)
- ✅ YARA integration (file, directory, APK scanning)
- ✅ YAML rule engine
- ✅ Threat correlation engine with confidence scoring

### Tooling

- ✅ Plugin SDK
- ✅ AI assistant (Ollama + OpenAI)
- ✅ Multi-format reports (HTML, Markdown, JSON, SARIF)
- ✅ Interactive HTML dashboard
- ✅ Diff engine (scan comparison)
- ✅ Search engine (fuzzy search)
- ✅ Live device monitoring

---

## v1.1.0 — Next Release 📋

### Detection

- 📋 WiFi security assessment (open networks, WEP, evil twin indicators)
- 📋 Bluetooth device enumeration and risk analysis
- 📋 USB connection history analysis
- 📋 Camera and microphone access audit
- 📋 Contact and SMS exfiltration detection

### Forensics

- 📋 Enhanced timeline with logcat correlation
- 📋 Browser history and cache analysis
- 📋 Messaging app data extraction (Signal, WhatsApp, Telegram)
- 📋 Clipboard monitoring detection
- 📋 Screenshot and screen recording detection

### Tooling

- 📋 Batch APK analysis (multiple APKs at once)
- 📋 Custom report templates (HTML/CSS)
- 📋 PDF report export
- 📋 CSV export for findings
- 📋 Slack/Teams notification integration

### DX

- 📋 Interactive onboarding wizard
- 📋 Plugin marketplace
- 📋 Auto-update mechanism
- 📋 Shell completion (bash, zsh, fish)

---

## v1.2.0 — Future 📋

### Advanced Analysis

- 📋 Network traffic capture (pcap generation)
- 📋 Certificate transparency log checking
- 📋 Encrypted partition detection and analysis
- 📋 OTA integrity verification
- 📋 SafetyNet/Play Integrity attestation analysis
- 📋 Samsung Knox policy analysis

### Enterprise

- 📋 Multi-device simultaneous scanning
- 📋 Fleet management dashboard
- 📋 Scheduled scan automation
- 📋 SIEM integration (Splunk, ELK)
- 📋 REST API for automation
- 📋 Role-based access control

### Forensics

- 📋 Volatility-style memory forensics (with root)
- 📋 SIM card forensics
- 📋 Camera forensics (EXIF, metadata)
- 📋 Cloud backup analysis
- 📋 Cross-device correlation

---

## v2.0.0 — Vision 💭

### Platform

- 💭 Web dashboard for visual analysis
- 💭 Real-time collaboration
- 💭 Cloud-synced (optional) scan history
- 💭 Mobile companion app
- 💭 VS Code extension

### Advanced

- 💭 Machine learning-based anomaly detection
- 💭 Automated threat intelligence correlation
- 💭 Supply chain analysis for APKs
- 💭 Code similarity detection
- 💭 Automated evidence packaging for legal proceedings

### Enterprise

- 💭 MDM integration
- 💭 Compliance reporting (OWASP MASVS, NIST)
- 💭 Audit trail with chain of custody
- 💭 Evidence encryption and digital signing
- 💭 Multi-tenant deployment

---

## How to Influence the Roadmap

1. **Vote on features** — React to roadmap issues on GitHub
2. **Submit proposals** — Open a feature request with your use case
3. **Contribute** — Implement features yourself (see [CONTRIBUTING.md](CONTRIBUTING.md))
4. **Sponsor** — Fund development of specific features

## Release Schedule

| Version | Target | Focus |
|---------|--------|-------|
| v1.0.0 | Now | Core platform |
| v1.1.0 | Q1 2026 | Enhanced detection + DX |
| v1.2.0 | Q2 2026 | Enterprise + advanced forensics |
| v2.0.0 | 2026+ | Platform evolution |

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-12-01

### Added

- **Interactive Menu** — 20-option numbered menu with split layout and centered ASCII banner
- **Quick Scan** — Fast root detection scan (~5 seconds)
- **Full Scan** — Comprehensive scan with all 14 analysis engines
- **Deep Scan** — Full scan plus SUID analysis and YARA scanning
- **App Analysis** — Targeted package analysis by name or package ID
- **APK Analysis** — Offline APK static analysis with androguard
- **Threat Hunt** — Keyword-based threat hunting across device findings
- **Root Detection** — Magisk, KernelSU, APatch, BusyBox, OverlayFS detection
- **Hooking Framework Detection** — Frida, Xposed, LSPosed, Riru, EdXposed
- **Boot Chain Analysis** — AVB, DM-Verity, Verified Boot, rollback index
- **Filesystem Forensics** — Root files, SUID binaries, suspicious executables, scripts
- **Network Analysis** — TCP connections, DNS config, VPN detection, reputation scoring
- **Malware Scanner** — Known malware DB, dangerous permission combos, suspicious patterns
- **Backdoor Detection** — Persistence mechanisms, hidden dirs, bind mounts, debug props
- **Crypto Miner Detection** — Running process analysis for mining indicators
- **Device Profiling** — 26-section comprehensive device information collection
- **Timeline Engine** — Event reconstruction from device logs and history
- **YARA Integration** — File, directory, and APK scanning with custom rule support
- **Rule Engine** — YAML-based conditional rule evaluation
- **Plugin SDK** — Extensible plugin system with discovery, loading, and registration
- **AI Assistant** — Ollama (local) and OpenAI (cloud) integration
- **Report Generation** — Markdown, HTML (interactive dashboard), JSON, SARIF formats
- **SQLite Persistence** — Async storage for scans, findings, baselines, timeline
- **Diff Engine** — Git-style scan comparison between two points in time
- **Search Engine** — Fuzzy search across all past scans and findings
- **Live Monitor** — Real-time device monitoring with heartbeat alerts
- **Package Resolution** — Type app names (e.g., "youtube") → auto-resolves to package IDs
- **Auto Reports** — Full/deep scans auto-generate HTML reports
- **Event Bus** — Async pub/sub with 25+ named lifecycle events
- **Configuration** — Hierarchical YAML config with sensible defaults
- **Database** — Async SQLite with tables for scans, findings, baselines, timeline
- **Default YARA Rules** — 7 built-in rules for common threat patterns
- **Default Correlation Rules** — 3 YAML-based correlation rules
- **One-Click Launcher** — `./run` script with auto-setup
- **CLI Subcommands** — `aegis scan`, `aegis apk`, `aegis hunt`, etc.

### Security

- All analysis is read-only — never modifies the target device
- Zero telemetry — all analysis runs locally
- Evidence-based findings with confidence scores — never binary declarations
- SQLite database stores all scan history for audit trails

## [0.1.0] - 2025-06-01

### Added

- Initial development release
- Core architecture: Hexagonal Architecture + DDD + Event Bus
- Basic scanning pipeline
- ADB adapter
- Domain models

[1.0.0]: https://github.com/0xhroot/aegisdroid/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/0xhroot/aegisdroid/releases/tag/v0.1.0

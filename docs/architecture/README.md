# AegisDroid Architecture

## Overview

AegisDroid follows **Hexagonal Architecture** (Ports & Adapters) combined with **Domain-Driven Design** and an **Event-Driven** async pipeline.

## Layers

```
┌─────────────────────────────────────────────────────┐
│                   CLI Layer                          │
│         (Interactive Menu / Typer Subcommands)       │
├─────────────────────────────────────────────────────┤
│               Application Layer                      │
│     (Scanner Engine / Report Generator / Database)   │
├─────────────────────────────────────────────────────┤
│                  Domain Layer                        │
│       (Domain Models / Port Interfaces / Config)     │
├─────────────────────────────────────────────────────┤
│                Adapter Layer                         │
│    (ADB / APK Analyzer / YARA / Plugin / AI)         │
├─────────────────────────────────────────────────────┤
│             Analysis Engines                         │
│  (Root / Boot / Threat / Malware / Backdoor /        │
│   Filesystem / Network / Timeline / Profiler)        │
└─────────────────────────────────────────────────────┘
```

## Key Principles

1. **Ports & Adapters**: Abstract interfaces in `core/interfaces.py`, implementations in separate adapter modules
2. **Domain-Driven Design**: Rich domain models in `core/domain.py` — 40+ dataclasses
3. **Event-Driven**: Async event bus with 25+ named events for loose coupling
4. **Single Responsibility**: Each module does one thing well
5. **Evidence-Based**: Every finding carries evidence, confidence, and mitigation

## Data Flow

```
User Input → CLI → Scanner Engine → Analysis Engines → Correlation Engine → Findings
                                                                                ↓
                                                                        SQLite Database
                                                                                ↓
                                                                        Report Generator
```

## Component Communication

- **Synchronous**: Within analysis engines (direct method calls)
- **Asynchronous**: Between scanner and engines (async/await)
- **Event Bus**: For cross-cutting concerns (scan lifecycle, device connection)

## Adding New Components

1. Define port interface in `core/interfaces.py`
2. Implement adapter in the appropriate module
3. Register with the scanner engine
4. Add domain models if needed
5. Write tests

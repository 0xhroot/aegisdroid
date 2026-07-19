# AegisDroid Plugins

This directory contains example plugins and plugin templates.

## Structure

```
plugins/
├── README.md           # This file
├── example_scanner/    # Example analysis plugin
│   ├── __init__.py
│   └── scanner.py
└── example_reporter/   # Example report plugin
    ├── __init__.py
    └── reporter.py
```

## Creating a Plugin

See [Plugin SDK Documentation](../docs/plugin-sdk/README.md).

## Installing Plugins

1. Place your plugin directory in `plugins/`
2. Ensure it has an `__init__.py`
3. Restart AegisDroid

## Distribution

Plugins can be distributed as:

- Local directories (place in `plugins/`)
- Python packages (install via pip)
- Entry points (register in pyproject.toml)

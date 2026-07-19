# Contributing to AegisDroid

Thank you for your interest in contributing to AegisDroid! This document provides guidelines and information for contributors.

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How to Contribute

### Reporting Bugs

1. Check [existing issues](https://github.com/aegisdroid/aegisdroid/issues) to avoid duplicates
2. Open a [bug report](https://github.com/aegisdroid/aegisdroid/issues/new?template=bug_report.md)
3. Include:
   - AegisDroid version (`aegis --version`)
   - Python version
   - OS and version
   - ADB version
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant logs or screenshots

### Suggesting Features

1. Open a [feature request](https://github.com/aegisdroid/aegisdroid/issues/new?template=feature_request.md)
2. Describe the problem the feature solves
3. Provide use cases
4. If possible, sketch the API or interface

### Contributing Code

#### Setup

```bash
# Fork and clone
git clone https://github.com/YOUR_USER/aegisdroid.git
cd aegisdroid

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in development mode
pip install -e ".[all]"

# Install pre-commit hooks
pre-commit install

# Run tests to verify setup
pytest tests/ -v
```

#### Development Workflow

1. Create a branch from `main`:
   ```bash
   git checkout -b feature/my-feature
   ```

2. Make your changes following the coding standards below

3. Add tests for new functionality

4. Run the full test suite:
   ```bash
   make test
   ```

5. Run linting:
   ```bash
   make lint
   ```

6. Commit using [Conventional Commits](https://www.conventionalcommits.org/):
   ```bash
   git commit -m "feat: add new root detection method"
   git commit -m "fix: resolve ADB connection timeout"
   git commit -m "docs: update installation guide"
   ```

7. Push and open a Pull Request

#### Branch Naming

| Prefix | Purpose |
|--------|---------|
| `feature/` | New features |
| `fix/` | Bug fixes |
| `docs/` | Documentation changes |
| `refactor/` | Code refactoring |
| `test/` | Test additions/changes |
| `chore/` | Maintenance tasks |

#### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix | Purpose | Example |
|--------|---------|---------|
| `feat:` | New feature | `feat: add KernelSU detection` |
| `fix:` | Bug fix | `fix: resolve ADB timeout on slow devices` |
| `docs:` | Documentation | `docs: update API reference` |
| `refactor:` | Code refactoring | `refactor: extract threat scoring logic` |
| `test:` | Tests | `test: add root detector unit tests` |
| `chore:` | Maintenance | `chore: update dependencies` |
| `perf:` | Performance | `perf: optimize YARA rule compilation` |
| `ci:` | CI/CD | `ci: add CodeQL workflow` |
| `style:` | Formatting | `style: fix ruff warnings` |

### Coding Standards

#### Python Style

- **Formatter/Linter**: Ruff (configured in `pyproject.toml`)
- **Type Checking**: Mypy with strict mode
- **Python Version**: 3.11+
- **Line Length**: 100 characters
- **Imports**: Sorted with isort (via Ruff)

#### Code Principles

- Use `from __future__ import annotations` in every module
- All I/O must be async (`async/await`)
- Type hints required on all functions
- No comments unless specifically requested
- Evidence-based findings only — never binary yes/no
- Each module should have a single responsibility
- Follow existing patterns in neighboring files

#### Testing

- Write tests for all new functionality
- Use `pytest-asyncio` for async tests
- Aim for 80%+ coverage
- Mark device-dependent tests with `@pytest.mark.requires_device`
- Mark slow tests with `@pytest.mark.slow`

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=aegisdroid --cov-report=term-missing

# Run specific test file
pytest tests/test_core/test_domain.py -v
```

### Adding a New Analysis Engine

1. Create module in appropriate directory:
   ```
   aegisdroid/threats/my_engine.py
   ```

2. Implement the engine class:
   ```python
   from aegisdroid.core.domain import Finding, Severity, ThreatCategory

   class MyEngine:
       def __init__(self, adb: Any) -> None:
           self._adb = adb

       async def scan(self) -> list[Finding]:
           findings: list[Finding] = []
           # Analysis logic here
           return findings
   ```

3. Integrate into `scanner/engine.py`

4. Add tests in `tests/`

5. Register with the event bus if needed

### Adding a YARA Rule

1. Create or edit `.yar` file in `rules/packs/`
2. Follow the existing rule structure:
   ```yara
   rule rule_name {
       meta:
           description = "What this rule detects"
           severity = "high"
       strings:
           $s1 = "pattern" ascii
       condition:
           any of them
   }
   ```
3. Test the rule with `aegis yara`

### Adding a Plugin

See the [README](README.md#plugin-sdk) for Plugin SDK details.

### Documentation

- Update relevant docs in `docs/` when changing functionality
- Use clear, concise language
- Include code examples where helpful
- Test all code examples

### Pull Request Guidelines

- PRs should target the `main` branch
- Fill out the PR template completely
- Link related issues
- Keep PRs focused — one feature/fix per PR
- Ensure CI passes before requesting review
- Add screenshots for UI changes
- Update documentation for user-facing changes

### Review Process

1. All PRs require at least one review
2. CI must pass (lint, tests, type checking)
3. Maintainers may request changes
4. Once approved, a maintainer will merge

### Recognition

Contributors are recognized in:
- The project's Contributors section
- Release notes
- The CHANGELOG.md

## Getting Help

- Open a [Discussion](https://github.com/aegisdroid/aegisdroid/discussions)
- Check the [README](README.md#troubleshooting) for common issues
- Review existing [Issues](https://github.com/aegisdroid/aegisdroid/issues)

Thank you for contributing to AegisDroid!

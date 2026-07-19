# Governance

This document describes how the AegisDroid project is governed.

## Project Structure

```
AegisDroid
├── Lead Maintainer(s)
│   ├── Architecture decisions
│   ├── Release management
│   └── Security response
├── Core Contributors
│   ├── Code review
│   ├── Feature development
│   └── Documentation
└── Community
    ├── Bug reports
    ├── Feature requests
    └── Contributions
```

## Roles

### Lead Maintainer

- Final decision authority on project direction
- Manages releases and versioning
- Handles security disclosures
- Sets coding standards
- Reviews and merges critical changes

### Core Contributor

- Reviews and merges non-critical PRs
- Develops new features
- Maintains documentation
- Participates in roadmap planning
- Triages issues

### Contributor

- Submits PRs for features, fixes, and docs
- Reviews other contributors' PRs
- Participates in discussions
- Reports bugs and suggests features

## Decision Making

### Consensus

Most decisions are made through informal consensus in GitHub Discussions or Issues.

### Voting

When consensus cannot be reached:

- Lead Maintainer makes the final decision
- Major architectural changes require approval from at least 2 core contributors
- The decision is documented in the relevant issue/PR

### Roadmap

Roadmap items are proposed as GitHub Issues and discussed publicly. Lead Maintainer has final say on prioritization.

## Release Process

1. Release candidate is created from `main`
2. Core contributors review and test
3. Release notes are drafted
4. Version is tagged (Semantic Versioning)
5. Artifacts are built and published
6. Release is announced

## Conflict Resolution

1. Discuss openly in the relevant issue/PR
2. If unresolved, Lead Maintainer mediates
3. If still unresolved, Lead Maintainer decides
4. The decision is documented

## Changes to Governance

Governance changes require:
- Open discussion in a GitHub Issue
- Approval from Lead Maintainer
- Documentation update

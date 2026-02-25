# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-02-25

### Added

- CLI tool to explain AWS IAM access denials (`iamwhy PRINCIPAL ACTION`)
- Principal resolution for IAM users, roles, and STS assumed-role sessions
- `SimulatePrincipalPolicy` wrapper with human-readable verdicts
- Denial cause analysis: explicit deny, implicit deny, SCP block, permissions boundary, missing context, combined
- Rich terminal output with policy statement details and decision breakdown
- JSON output format (`--output json`)
- Resource ARN targeting (`--resource`)
- Context key injection (`--context KEY=VALUE`)
- AWS profile and region options (`--profile`, `--region`)
- Exit codes: 0 (allowed), 1 (denied), 2 (error)

[0.1.0]: https://github.com/Specter099/iamwhy/releases/tag/v0.1.0

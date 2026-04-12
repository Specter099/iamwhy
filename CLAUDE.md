# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

iamwhy is a Python CLI tool that explains why AWS IAM access is denied by tracing policies, statements, and conditions. It uses the IAM Policy Simulator API to evaluate access and presents human-readable verdicts. Built with Click, boto3, and Rich.

## Setup

```
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Common Commands

```
# Explain an IAM denial
.venv/bin/iamwhy arn:aws:iam::123456789012:user/alice s3:GetObject
.venv/bin/iamwhy alice s3:GetObject --resource arn:aws:s3:::my-bucket/*
.venv/bin/iamwhy my-role ec2:RunInstances --context aws:SourceIp=1.2.3.4
.venv/bin/iamwhy alice s3:PutObject --output json

# Run tests
.venv/bin/pytest

# Lint
.venv/bin/ruff check .

# Security audit
.venv/bin/pip-audit
```

## Directory Structure

```
src/iamwhy/
  cli.py          # Click CLI entry point
  resolver.py     # Resolves principal ARNs from usernames, role names, or STS ARNs
  simulator.py    # Calls iam:SimulatePrincipalPolicy and builds context entries
  analyzer.py     # Analyzes simulation results into human-readable verdicts
  formatters.py   # Text and JSON output formatters
  models.py       # Data models (DecisionType, PrincipalInfo, Verdict)
tests/
  conftest.py     # Shared fixtures
  test_cli.py     # CLI integration tests
  test_resolver.py    # Principal resolver tests
  test_simulator.py   # Simulator tests
  test_analyzer.py    # Analyzer tests
  test_formatters.py  # Formatter tests
  test_models.py      # Model tests
```

## Architecture

Single-command Click CLI (`iamwhy.cli:main`, installed as `iamwhy`). Source code uses the src layout with hatchling build system (`src/iamwhy/`).

Pipeline: resolve principal (username/role name to ARN) -> simulate access via IAM Policy Simulator -> analyze results (match policies, statements, conditions) -> format output.

Exit codes: 0 = allowed, 1 = denied, 2 = input/AWS error.

The caller needs `iam:SimulatePrincipalPolicy`, `iam:GetUser`, and `iam:GetRole` permissions.

## Testing

Tests use `pytest` with `moto[iam]` for mocking AWS IAM. Coverage is configured with an 80% minimum threshold.

```
.venv/bin/pytest                        # Run all tests
.venv/bin/pytest tests/test_analyzer.py # Run specific test file
.venv/bin/pytest -x                     # Stop on first failure
.venv/bin/coverage run -m pytest        # Run with coverage
.venv/bin/coverage report               # Show coverage report
```

## Code Style

Ruff is configured with line-length 88, targeting Python 3.11. Rules: E, F, I, W, S, B (includes bandit security checks). Tests are exempted from S101 (assert usage).

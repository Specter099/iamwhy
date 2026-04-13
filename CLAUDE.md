# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

CLI tool that explains why AWS IAM access is denied by calling `SimulatePrincipalPolicy`, tracing the decision through identity policies, SCPs, permissions boundaries, and missing context keys. Built with Click, boto3, and Rich. Published to PyPI as `iamwhy`.

## Setup

python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

## Common Commands

# Run tests with coverage
.venv/bin/coverage run -m pytest

# Check coverage threshold (fail_under = 80%)
.venv/bin/coverage report

# Lint
.venv/bin/ruff check src/ tests/

# Format check
.venv/bin/ruff format --check src/ tests/

# Auto-fix lint and format
.venv/bin/ruff check --fix src/ tests/
.venv/bin/ruff format src/ tests/

# Dependency audit
.venv/bin/pip-audit

# CLI usage
iamwhy arn:aws:iam::123456789012:user/alice s3:GetObject --resource "arn:aws:s3:::my-bucket/*"
iamwhy MyRole ec2:DescribeInstances --output json --profile dev

## Directory Structure

src/iamwhy/
  cli.py          # Click entry point — arg parsing, session setup, exit codes
  resolver.py     # Resolves ARNs/bare names to PrincipalInfo, enumerates attached policies
  simulator.py    # Wrapper around SimulatePrincipalPolicy API
  analyzer.py     # Interprets SimulationResult into a Verdict with cause/summary
  formatters.py   # Rich text and JSON output renderers
  models.py       # Pure dataclasses/enums — no I/O
tests/            # pytest + moto[iam] + pytest-mock — mirrors src/ structure

## Architecture

The CLI pipeline is sequential: **resolve principal → simulate → analyze → format**.

- `resolver.py` accepts IAM ARNs, STS assumed-role ARNs, or bare user/role names and normalizes to a `PrincipalInfo`.
- `simulator.py` calls `SimulatePrincipalPolicy` for a single action and returns a `SimulationResult`.
- `analyzer.py` maps the raw AWS decision to a `Verdict` with a `DenialCause` enum (explicit deny, implicit deny, SCP, permissions boundary, missing context, or combined). Optionally fetches the actual policy statement text via `GetPolicy`/`GetPolicyVersion`.
- `formatters.py` renders the verdict as either Rich terminal output or JSON.
- All data flows through frozen dataclasses in `models.py`. No mutable state.

Exit codes: 0 = allowed, 1 = denied, 2 = input/permission error.

## Code Style

- Ruff for linting and formatting. Line length 88, target Python 3.11.
- Lint rules: E, F, I, W, S (bandit), B (bugbear). `assert` allowed in tests.
- Build system: Hatchling. Package lives under `src/iamwhy/`.

## Testing

- Framework: pytest with `moto[iam]` for AWS mocking and `pytest-mock` for patching.
- Coverage enforced at 80% minimum (`coverage report` will fail below threshold).
- Tests mirror source layout: `test_analyzer.py`, `test_cli.py`, `test_formatters.py`, `test_models.py`, `test_resolver.py`, `test_simulator.py`.

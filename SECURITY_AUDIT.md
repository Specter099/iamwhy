# Security Audit Report — iamwhy

**Date:** 2026-02-25
**Scope:** Full codebase review (src/, tests/, CI/CD, dependencies, configuration)
**Auditor:** Automated security review

---

## Executive Summary

`iamwhy` is a Python CLI tool that queries AWS IAM APIs to explain access denials. The codebase is small (~1,100 lines of source) and well-structured. No critical vulnerabilities such as remote code execution, injection, or credential leakage were found. However, there are **13 findings** across CI/CD supply chain security, error handling correctness, and operational hardening that should be addressed before a production/PyPI release.

| Severity | Count |
|----------|-------|
| High     | 3     |
| Medium   | 5     |
| Low      | 5     |

---

## HIGH Severity Findings

### H1. No CI Pipeline for Tests or Linting

**Location:** `.github/workflows/` (missing)
**Category:** CI/CD, Quality Gate

The repository has a `release.yml` workflow (build + publish on tag push) and a `stale.yml` bot, but **no CI workflow that runs tests, linting, or security checks on pull requests or pushes**. This means:

- Code can be merged to `main` without passing any automated checks.
- Regressions, broken tests, or lint violations are not caught before release.
- The 80% coverage requirement in `pyproject.toml` is never enforced in CI.

**Recommendation:** Add a `.github/workflows/ci.yml` that triggers on `push` and `pull_request` to `main`:
```yaml
jobs:
  test:
    steps:
      - run: pip install -e ".[dev]"
      - run: ruff check src/ tests/
      - run: ruff format --check src/ tests/
      - run: coverage run -m pytest && coverage report
```
Require this check to pass via branch protection rules before merging.

---

### H2. GitHub Actions Pinned to Mutable Tags (Supply Chain Risk)

**Location:** `.github/workflows/release.yml:15,18,29`
**Category:** Supply Chain Security

All GitHub Actions are referenced by mutable version tags:
```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
- uses: softprops/action-gh-release@v2
```

A compromised or force-pushed tag could inject malicious code into the release pipeline, which has `contents: write` permission. The `softprops/action-gh-release` is a third-party action, which carries higher risk.

**Recommendation:** Pin all actions to their full commit SHA:
```yaml
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
- uses: actions/setup-python@82c7e631bb3cdc910f68e0081d67478d79c6982d  # v5.1.0
- uses: softprops/action-gh-release@9d7c94cfd0a1f3ed45544c887983e9fa900f0564  # v2.0.4
```
Add a comment with the human-readable version for maintainability.

---

### H3. No Dependency Lock File — Non-Reproducible Builds

**Location:** `pyproject.toml:28-32,38-44`
**Category:** Supply Chain Security, Reproducibility

Dependencies use open-ended lower-bound constraints (`boto3>=1.34`, `click>=8.1`, etc.) with no upper bounds and no lock file (`requirements.lock`, `pip-tools` constraints, or `uv.lock`). This means:

- Builds are not reproducible — two installs at different times may resolve different dependency versions.
- A compromised or yanked upstream package version can be pulled in silently.
- The release workflow builds from unlocked dependencies, so a released artifact's dependency tree is unpredictable.

**Recommendation:**
1. Add upper-bound constraints or use compatible-release syntax (e.g., `boto3>=1.34,<2`).
2. Generate and commit a lock file using `pip-compile` (pip-tools), `uv lock`, or equivalent.
3. In the release workflow, install from the lock file to ensure reproducible builds.

---

## MEDIUM Severity Findings

### M1. Silent Error Swallowing During Group Policy Enumeration

**Location:** `src/iamwhy/resolver.py:209-210`
```python
except ClientError:
    pass
```

**Issue:** When enumerating group policies for a user, **all** `ClientError` exceptions (including `AccessDenied`, throttling, service errors) are silently ignored. This means:

- If the caller lacks `iam:ListGroupsForUser` permissions, group-attached policies are silently omitted.
- The resulting verdict may be **misleading** — a user could be told access is denied by an identity policy when a group policy actually grants (or explicitly denies) access.
- There is no indication to the user that the analysis is incomplete.

**Recommendation:** At minimum, log a warning or emit a diagnostic message to stderr when this fallback triggers. Differentiate between expected `AccessDenied` (degrade gracefully with a warning) and unexpected errors (propagate or report).

---

### M2. Overly Broad Exception Handling in Policy Fetching

**Location:** `src/iamwhy/analyzer.py:228`
```python
except (ClientError, Exception):
```

**Issue:** Catching bare `Exception` alongside `ClientError` is redundant (`ClientError` is already a subclass of `Exception`) and overly broad. This silently swallows:
- `TypeError`, `KeyError`, `IndexError` from malformed API responses
- `json.JSONDecodeError` from corrupt policy documents
- Any programming bug in the fetch logic

These errors should be surfaced during development and testing rather than silently degraded.

**Recommendation:** Narrow the catch to specific expected exceptions:
```python
except ClientError:
    # Degrade gracefully — insufficient permissions
    ...
```
Let unexpected errors propagate so they can be caught and fixed.

---

### M3. Only First Policy Statement Returned — Incomplete Analysis

**Location:** `src/iamwhy/analyzer.py:249`, `src/iamwhy/analyzer.py:288`
```python
raw = statements[0] if statements else None
```

**Issue:** Both `_fetch_managed_policy_source` and `_fetch_inline_policy_source` only extract the **first** statement from a policy document. IAM policies frequently contain multiple statements (e.g., one Allow and one Deny). The actual blocking statement may be the 2nd, 3rd, or nth entry.

**Impact:** The tool may display the wrong statement to the user, leading them to troubleshoot the wrong policy rule.

**Recommendation:** Cross-reference `MatchedStatements` data (which includes `SourcePolicyId` and statement index/SID) to select the correct statement, or return all statements and let the formatter display the relevant one.

---

### M4. No Dependency Vulnerability Scanning

**Location:** `pyproject.toml`, `.github/workflows/` (missing)
**Category:** Supply Chain Security

There is no automated dependency vulnerability scanning:
- No GitHub Dependabot configuration (`.github/dependabot.yml`)
- No `pip-audit` or `safety` check in CI
- No SBOM (Software Bill of Materials) generation

**Recommendation:**
1. Add `.github/dependabot.yml` for automated dependency update PRs.
2. Add `pip-audit` to the CI pipeline.
3. Consider generating an SBOM as part of the release workflow.

---

### M5. Release Artifacts Are Unsigned and Unattested

**Location:** `.github/workflows/release.yml`
**Category:** Supply Chain Integrity

The release workflow builds a wheel and attaches it to a GitHub Release, but:
- No cryptographic signing of artifacts (GPG or Sigstore)
- No SLSA provenance attestation
- No hash verification published alongside the artifacts

Users downloading the release have no way to verify its authenticity or that it was built from the tagged source.

**Recommendation:**
1. Add `gh attestation create` or use `slsa-framework/slsa-github-generator` for provenance.
2. When publishing to PyPI, use Trusted Publishers (OIDC) instead of API tokens.
3. Publish SHA256 checksums alongside release artifacts.

---

## LOW Severity Findings

### L1. Ruff Linting Rules Miss Security-Relevant Checks

**Location:** `pyproject.toml:66`
```toml
select = ["E", "F", "I", "W"]
```

**Issue:** Only basic PEP 8, PyFlakes, import sorting, and warning rules are enabled. Notable omissions:
- `S` (flake8-bandit) — detects hardcoded passwords, `eval()`, insecure hash functions, etc.
- `B` (flake8-bugbear) — catches common correctness bugs
- `UP` (pyupgrade) — enforces modern Python patterns
- `T20` (flake8-print) — flags leftover `print()` calls in library code

**Recommendation:** Enable at least `S` and `B`:
```toml
select = ["E", "F", "I", "W", "S", "B"]
```

---

### L2. `_account_from_arn` Returns Empty String on Invalid Input

**Location:** `src/iamwhy/resolver.py:166-169`
```python
def _account_from_arn(arn: str) -> str:
    parts = arn.split(":")
    return parts[4] if len(parts) >= 5 else ""
```

**Issue:** If an ARN has fewer than 5 colon-separated parts, the function returns an empty string instead of raising an error. This means a `PrincipalInfo` could have `account_id=""`, which is silently incorrect and could confuse downstream consumers (especially in JSON output).

**Recommendation:** Raise a `ValueError` for malformed ARNs since this function is only called after the ARN regex has already matched (a defense-in-depth check).

---

### L3. JSON Output Provides Less Detail Than Text Output

**Location:** `src/iamwhy/cli.py:115`
```python
fetch = output != "json"  # skip GetPolicyVersion for JSON — reduces API calls
```

**Issue:** When `--output json` is used, `fetch_statements` is set to `False`, meaning policy statement text is never fetched. Users piping JSON to automated tooling get an incomplete picture of the denial — `blocking_policies[].statement` will always be `null`.

**Recommendation:** Either fetch statements for both output modes (removing the optimization), or add a `--fetch-statements` / `--no-fetch-statements` flag so users can opt in explicitly.

---

### L4. No Logging Framework — Diagnostics Only via stderr Print

**Location:** All of `src/iamwhy/`
**Category:** Operational Security

The tool has no structured logging. Diagnostics are written directly to stderr via `Console.print()`. This means:
- No log levels — no way to enable debug output for troubleshooting
- No structured output for log aggregation in automated environments
- The `--debug` flag mentioned in the roadmap (`tasks/todo.md`) is not yet implemented

**Recommendation:** Adopt Python `logging` with a `--debug` / `--verbose` flag that increases log verbosity. In the default mode, keep stderr clean. In debug mode, emit structured logs of each API call and decision step.

---

### L5. Author Personal Email in pyproject.toml

**Location:** `pyproject.toml:13`
```toml
authors = [{ name = "Specter099", email = "bel136@gmail.com" }]
```

**Issue:** A personal email address is embedded in package metadata that will be published to PyPI. This is a minor information disclosure that could be used for targeted phishing or social engineering.

**Recommendation:** Use a project-specific email, a GitHub noreply address, or omit the email field entirely if not required.

---

## Positive Findings

The audit also identified several **good security practices** already in place:

1. **No hardcoded credentials** — AWS credentials are handled exclusively through boto3's standard credential chain.
2. **Test isolation with moto** — The `conftest.py` fixture auto-injects fake AWS credentials and uses `mock_aws` to prevent accidental real API calls during testing.
3. **Frozen dataclasses** — All data models use `frozen=True`, preventing accidental mutation after construction.
4. **Clean separation of concerns** — I/O, AWS calls, business logic, and formatting are well-separated, reducing the attack surface of each module.
5. **Proper error handling in CLI** — AWS `ClientError` is caught and translated to user-friendly messages without leaking stack traces.
6. **Click's built-in input validation** — The CLI framework validates `--output` choices and handles type coercion safely.

---

## Summary of Recommendations (Priority Order)

| # | Finding | Action |
|---|---------|--------|
| H1 | No CI pipeline | Add CI workflow with tests, linting, coverage |
| H2 | Mutable action tags | Pin GitHub Actions to commit SHAs |
| H3 | No lock file | Add dependency lock file and upper bounds |
| M1 | Silent group policy error | Warn user when analysis is degraded |
| M2 | Broad exception catch | Narrow to `ClientError` only |
| M3 | First-statement-only | Return the matched statement, not just the first |
| M4 | No dep scanning | Add Dependabot + pip-audit |
| M5 | Unsigned releases | Add artifact signing/attestation |
| L1 | Limited lint rules | Enable `S` (bandit) and `B` (bugbear) rules |
| L2 | Empty account fallback | Raise on malformed ARN |
| L3 | JSON skips statements | Add explicit flag or fetch for both modes |
| L4 | No logging | Add structured logging with debug flag |
| L5 | Personal email | Use project email or omit |

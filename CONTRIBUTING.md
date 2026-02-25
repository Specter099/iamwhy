# Contributing to iamwhy

Thanks for your interest in contributing to iamwhy! This guide covers everything
you need to get started.

## Getting Started

1. Fork the repository and clone your fork:

   ```bash
   git clone https://github.com/<your-username>/iamwhy.git
   cd iamwhy
   ```

2. Create a virtual environment and install dev dependencies:

   ```bash
   python3.11 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

3. Verify everything works:

   ```bash
   pytest
   ```

## Development Workflow

1. Create a feature branch from `main`:

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes. Write tests for new functionality.

3. Run the checks before committing:

   ```bash
   # Lint and format
   ruff check --fix src/ tests/
   ruff format src/ tests/

   # Run tests
   pytest

   # Check coverage (must stay above 80%)
   coverage run -m pytest && coverage report
   ```

4. Commit your changes (see commit message conventions below).

5. Push and open a pull request against `main`.

## Code Style

This project uses [Ruff](https://docs.astral.sh/ruff/) for linting and formatting.
Configuration lives in `pyproject.toml`.

```bash
# Check for lint issues
ruff check src/ tests/

# Auto-fix lint issues
ruff check --fix src/ tests/

# Format code
ruff format src/ tests/

# Check formatting without changing files
ruff format --check src/ tests/
```

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` — new feature
- `fix:` — bug fix
- `docs:` — documentation only
- `test:` — adding or updating tests
- `chore:` — maintenance (deps, config, CI)
- `refactor:` — code change that neither fixes a bug nor adds a feature

Examples:

```
feat: add support for resource-based policies
fix: handle missing policy version gracefully
docs: add examples for SCP analysis
```

## Pull Requests

- All PRs require maintainer review before merging.
- Target the `main` branch.
- Include a clear description of what your change does and why.
- Make sure all tests pass and coverage stays above 80%.
- Keep PRs focused — one logical change per PR.

## Testing

Tests use [pytest](https://docs.pytest.org/) with [moto](https://docs.getmoto.org/)
for AWS mocking. No real AWS credentials are needed to run the test suite.

```bash
# Run all tests
pytest

# Run a specific test file
pytest tests/test_analyzer.py

# Run with coverage
coverage run -m pytest && coverage report
```

When adding new functionality, write tests that cover both the happy path and
edge cases.

## Reporting Bugs & Requesting Features

Open an issue on GitHub. For bugs, include:

- What you expected to happen
- What actually happened
- Steps to reproduce
- Python version and OS

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](LICENSE).

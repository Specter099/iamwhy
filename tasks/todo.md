# iamwhy — task backlog

## Done (v0.1.0)
- [x] models.py — frozen dataclasses for all domain types
- [x] resolver.py — principal ARN normalization + policy enumeration
- [x] simulator.py — SimulatePrincipalPolicy wrapper with pagination
- [x] analyzer.py — verdict logic (explicit deny, implicit deny, SCP, boundary, missing context)
- [x] formatters.py — Rich text + JSON output
- [x] cli.py — Click entry point with proper exit codes
- [x] Full test suite (pytest + moto + pytest-mock)

## Backlog

### Features
- [ ] `--resource-policy FILE` — supply a resource-based policy JSON and include it in simulation
- [ ] Multiple actions in one invocation: `iamwhy alice s3:GetObject s3:PutObject`
- [ ] `--explain-scp` — fetch and display the blocking SCP document (requires Organizations read access)
- [ ] `--explain-boundary` — display the permissions boundary document
- [ ] Session-tag context: `--session-tag KEY=VALUE`
- [ ] Support for federated/OIDC principals
- [ ] Color themes (no-color / ANSI fallback for CI)

### Polish
- [ ] Progress spinner for slow API calls (rich.progress)
- [ ] Cache resolved principals + policy documents within a session
- [ ] `--quiet` flag: suppress breakdown, output only verdict + cause
- [ ] Structured logging with `--debug`

### Distribution
- [ ] PyPI publish workflow (GitHub Actions)
- [ ] Homebrew formula
- [ ] Docker image (`python:3.11-slim`)

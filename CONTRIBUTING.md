# Contributing

## Quick Start

```powershell
git clone https://github.com/KiaroSama/megabasterd-cli.git
cd megabasterd-cli

# Source launcher path
.\Run.ps1 --help

# Development environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
pre-commit install
```

## Workflow

1. Open an issue for non-trivial changes.
2. Create a topic branch.
3. Keep edits focused and add tests for changed behavior.
4. Run local checks.
5. Open a pull request with a short behavior summary and test results.

## Local Checks

```powershell
ruff check src tests
black --check src tests
mypy src/megabasterd_cli --ignore-missing-imports
pytest
.\Run.ps1 --help
```

## Project Layout

```text
Run.ps1                  # Source launcher
src/megabasterd_cli/     # Importable package
tests/                   # Unit tests
docs/                    # User and developer documentation
.github/                 # Issue templates and CI workflows
```

Inside `src/megabasterd_cli`:

```text
commands/     Click command adapters
core/         MEGA protocol, crypto, transfer engines, link parsing
accounts/     Encrypted account vault
proxy/        Smart proxy pool and CONNECT proxy
queue/        Persistent transfer queue
streaming/    Local HTTP streaming server
ui/           Rich theme, prompts, tables, progress bars
utils/        Logging, helpers, hooks, speed limiting
```

## Coding Conventions

- Target Python 3.10+.
- Prefer tested core helpers over command-level logic.
- Keep command modules thin.
- Use `ui.theme.make_console()` for Rich output.
- Use existing style names from `ui/theme.py` before adding new visual styles.
- Avoid broad refactors when a focused fix is enough.
- Do not log secrets, account passwords, share keys, or vault passphrases.

## Tests

Tests should cover:

- new link formats and parser behavior;
- cryptographic transformations with deterministic fixtures;
- transfer state and resume behavior;
- command registration and important help surfaces;
- error paths where user-facing behavior matters.

For network-dependent behavior, prefer unit tests with fakes unless the test is
explicitly marked and documented as live.

## Pull Request Checklist

- `pytest` passes.
- `ruff check src tests` passes.
- `black --check src tests` passes.
- `.\Run.ps1 --help` runs.
- Documentation is updated when user-visible behavior changes.
- New config keys are documented in `docs/CONFIG.md`.

## Reporting Bugs

Include:

- OS and Python version;
- command used;
- sanitized error output;
- whether the issue happens through `Run.ps1`, installed `mb`, or both;
- `-vv` logs when useful, with secrets removed.

## Security Issues

Do not open public issues for security-sensitive problems. Use the contact path
in [SECURITY.md](SECURITY.md).

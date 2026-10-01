# Changelog

All notable changes to VibeGuard will be documented in this file.

## [Unreleased]

### Added

- GitHub Actions CI workflow with a test matrix on Python 3.11/3.12 and a ruff lint job.
- Ruff and pytest configuration in `pyproject.toml`.
- Future additions will be documented here.

### Changed

- Future changes will be documented here.

### Fixed

- Fixed bare `pytest` collection failing on the intentionally vulnerable `test_vulnerable_app.py` fixture by scoping `testpaths` to `tests/`.
- Addressed lint findings in the scanner and rule modules (unused imports, import ordering, `datetime.UTC`, `StrEnum` severity, single-call `startswith`).
- Future fixes will be documented here.

### Removed

- Future removals will be documented here.

## [0.1.0] - 2026-09-15

### Added

- Initial VibeGuard security scanner functionality.
- Security rules for detecting common issues in AI-generated code.
- Command-line scanning support.
- JSON and SARIF output support.

# Changelog

All notable changes to VibeGuard will be documented in this file.

## [Unreleased]

### Added

- GitHub Actions CI workflow with a test matrix on Python 3.11/3.12 and a ruff lint job.
- Ruff and pytest configuration in `pyproject.toml`.
- `Publish to PyPI` release workflow using trusted publishing (`id-token: write`, environment `pypi`), so the first release has a publish path at all.
- `tests/test_distribution_name.py`, which fails the build if any tracked surface ever tells a reader to install a forbidden bare name again.
- Future additions will be documented here.

### Changed

- Renamed the distribution from `vibeguard` to `vibeguard-py`. The bare `vibeguard` name on PyPI belongs to an unrelated third-party project by a different author, so the old name could never be published under this project's account, and every `pip install vibeguard` in the docs silently installed someone else's package. Only the distribution name moves: the console script, the importable module and the repository name stay `vibeguard`.
- Replaced every documented install line with `pip install git+https://github.com/yunaremaia/vibeguard.git`, since the package is not on PyPI yet.
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

# Changelog

All notable changes to VibeGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-03

First tagged release. `0.1.0` is the version already declared in `pyproject.toml`;
nothing was ever tagged or published before this date, so everything below ships
together as the initial release. The previously separate "Unreleased" entries are
folded in here rather than shipped as an empty section.

### Not on PyPI

**`vibeguard-py` is not on PyPI and `pip install vibeguard-py` does not work.**
Install from git:

```bash
pip install git+https://github.com/yunaremaia/vibeguard.git
```

Two independent reasons:

- The PyPI project has no trusted publisher registered for this repository yet,
  so the `Publish to PyPI` workflow has no way to upload until that is configured.
- The distribution name carries a `-py` suffix because the bare `vibeguard` name on
  PyPI belongs to an unrelated project by a different author. Publishing under the
  bare name is not possible, and `pip install vibeguard` would silently install
  someone else's package.

The repository name, the importable module (`vibeguard`) and the `vibeguard`
console script are unaffected by the distribution rename.

### Added

**Scanner and rules**

- Six security rules covering the failure modes that show up in AI-generated code:
  - `VGB-001` hardcoded secrets — API keys, AWS access key IDs, generic
    token/secret/password assignments, and committed private keys.
  - `VGB-002` SQL injection — string-formatted SQL in `execute`/`query` calls.
  - `VGB-003` dangerous functions — `eval`, `exec`, `pickle.loads`, `os.system`,
    `subprocess` with `shell=True` and similar.
  - `VGB-004` / `VGB-005` CORS — wildcard origins combined with credentials, and
    permissive origin reflection.
  - `VGB-006` missing authentication — framework routes reachable without an auth
    check, with common public-path exclusions (`/health`, `/docs`, `/login`, ...)
    so routes that are meant to be open are not flagged.
- Directory and single-file scanning via `vibeguard <target>`.
- Three output formats: `text` (default, colored terminal report), `json`, and
  `sarif` 2.1.0 for GitHub Code Scanning.
- `--format`, `--output`, `--min-severity`, and `--version` / `-v` / `-V` flags
  (`--version` reads the package `__version__`, so it cannot drift from
  `pyproject.toml`).
- Documented CLI exit codes for use as a CI gate.

**Project infrastructure**

- GitHub Actions CI with a test matrix on Python 3.11 and 3.12 plus a `ruff` lint
  job, and a `Publish to PyPI` workflow using trusted publishing
  (`id-token: write`, environment `pypi`).
- A 100% line-coverage gate (`fail_under` in `pyproject.toml`), ratcheted at the
  value the suite actually measures rather than a round figure.
- `tests/test_distribution_name.py`, which fails the build if any tracked surface
  ever tells a reader to install a forbidden bare name again.
- `Dockerfile` for containerized use.
- `docs/API.md` — API reference for the scanner, formatters and CLI.
- `CONTRIBUTING.md`, `SECURITY.md`, `FUNDING.yml`, an MIT `LICENSE`, and PR,
  bug-report and feature-request templates.

### Fixed

- ReDoS and OOM exposure: lines longer than 50 KB are truncated before regex
  matching and files larger than 10 MB are skipped, so a minified or generated
  file cannot cause catastrophic backtracking or exhaust memory.
- Path traversal via symlinks: a symlink resolving outside the target directory
  is rejected instead of followed, so scanning a directory cannot be redirected
  into reading arbitrary files.
- The generic token/password rule never matched a real credential. Its `/`
  exclusion sat outside the character class, compiling to "quote, one character,
  8 or more slashes, quote". The exclusion now sits inside the class, so the rule
  matches quoted literals while still skipping URLs and format placeholders.
- Bare `pytest` collection failed on the intentionally vulnerable
  `test_vulnerable_app.py` fixture; `testpaths` is scoped to `tests/`, and that
  file is excluded from lint and coverage as fixture data.
- Lint findings in the scanner and rule modules (unused imports, import order,
  `datetime.UTC`, `StrEnum` severity, single-call `startswith`).

### Changed

- Renamed the distribution from `vibeguard` to `vibeguard-py`; only the
  distribution name moves.
- Replaced every documented install line with the git-based install above.
- Ruff lint configuration is now an explicit pinned rule set
  (`E`, `F`, `B`, `I`, `UP`, `PIE`, `RUF`, `S`) instead of ruff's
  version-dependent defaults, so CI fails for the same reasons on every run.
- Pytest and ruff configuration now live in `pyproject.toml`.

[0.1.0]: https://github.com/yunaremaia/vibeguard/releases/tag/v0.1.0
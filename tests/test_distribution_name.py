"""Regression guards for the documented install instructions.

The distribution name is read from ``[project] name`` in pyproject.toml, never
hardcoded, so a future rename cannot leave the docs pointing at a package that
does not exist. Two facts are pinned here:

1. Nothing is published on PyPI yet, so the docs must install from git. Any bare
   ``pip install <name>`` line in the docs is a 404 for a reader -- and a runtime
   failure for anyone who copies the GitHub Actions example, because that line
   really does execute ``pip install``.
2. The short name ``vibeguard`` on PyPI belongs to an unrelated third-party
   project, so it must never be offered as an install target either.

Rule 1 is deliberately the one that flips on publication. Publishing is gated on
creating the project on PyPI and registering a trusted publisher; once
``pip install vibeguard-py`` resolves, the git line becomes unnecessary and the
bare install becomes correct. Flip ``PUBLISHED`` in that same commit -- do not
leave a guard that forces one of two wrong states.
"""

from __future__ import annotations

import re
import shlex
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
PYPROJECT = REPO_ROOT / "pyproject.toml"

# Flip to True in the same commit that restores the PyPI install line, once
# https://pypi.org/pypi/<the [project] name>/json answers 200.
PUBLISHED = False

# Every tracked surface a reader can copy an install line out of.
DOC_SURFACES = (
    "README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CHANGELOG.md",
    "Dockerfile",
    "action.yml",
    ".pre-commit-hooks.yaml",
    "docs/API.md",
)

_PYPROJECT = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
DIST_NAME: str = _PYPROJECT["project"]["name"]

# The repository owner and name, parsed out of the declared homepage. The repo
# name is the *short* name on PyPI -- the one owned by someone else -- so it is
# the value that must never appear as a bare install target.
_HOMEPATH = re.match(
    r"https://github\.com/([^/]+)/([^/.]+)", _PYPROJECT["project"]["urls"]["Homepage"]
).groups()
OWNER, REPO_NAME = _HOMEPATH

# Hardcoded on purpose: these are facts about somebody else's PyPI project, not
# about this repository, so a rename here cannot change them.
FOREIGN_NAME = "vibeguard"

EXPECTED_INSTALL = (
    f"pip install {DIST_NAME}"
    if PUBLISHED
    else f"pip install git+https://github.com/{OWNER}/{REPO_NAME}.git"
)

# Install targets that must never appear. While unpublished, a bare
# `pip install vibeguard-py` 404s just like the short name does; the short name
# fails worse, by silently installing another author's project.
FORBIDDEN_TARGETS = {FOREIGN_NAME} | (set() if PUBLISHED else {DIST_NAME})

# `pip install`, `pip3 install`, `uv tool install`, `uv pip install` and
# `python -m pip install`, plus everything after them on the line.
INSTALL_COMMAND = re.compile(
    r"(?:uv\s+(?:tool|pip)|pip3?|python3?\s+-m\s+pip)\s+install(?P<args>[^\n]*)",
    re.M,
)

# A PEP 508 requirement: a bare name, optional extras, optional version spec.
#
# The negative lookahead `(?![\w.-])` is load-bearing. A plain substring check
# for "pip install vibeguard" is True for "pip install vibeguard-py", so the
# naive grep would flag the very line it is meant to protect. Anchoring the name
# and refusing to stop mid-token keeps the two apart.
#
# This also rejects, for free, every target that is not a bare name: a `git+`
# URL fails the spec part at the `+`, and `.` / `.[dev]` never start with an
# alphanumeric.
REQUIREMENT = re.compile(
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?![\w.-])"
    r"(?P<spec>\[[^\]]*\])?(?:[<>=!~].*)?$"
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _requirement_name(token: str) -> str | None:
    """Return the distribution name a pip target token names, if it names one."""
    match = REQUIREMENT.match(token)
    return match.group("name") if match else None


def install_targets(line: str) -> list[str]:
    """Return the distribution names pip would be handed by an install command."""
    names = []
    for command in INSTALL_COMMAND.finditer(line):
        try:
            tokens = shlex.split(command.group("args"))
        except ValueError:
            tokens = command.group("args").split()
        for token in tokens:
            if token.startswith("-"):  # -e, --upgrade, -r, --no-cache-dir ...
                continue
            name = _requirement_name(token)
            if name is not None:
                names.append(name)
    return names


def bare_install_lines(text: str) -> list[str]:
    """Return every line in *text* that installs a forbidden bare target.

    Only the tokens pip would actually receive are considered, so options and
    their values never register: a legitimate `git clone` + `pip install -e .`
    from-source block cannot show up as an offender.
    """
    return [
        line.strip()
        for line in text.splitlines()
        if FORBIDDEN_TARGETS.intersection(install_targets(line))
    ]


def doc_surfaces() -> list[tuple[str, Path]]:
    """The DOC_SURFACES that exist in this checkout."""
    return [(name, REPO_ROOT / name) for name in DOC_SURFACES if (REPO_ROOT / name).exists()]


class TestDocsInstallFromGitWhileUnpublished:
    """The expected install line is asserted first, so a failure names the fix."""

    def test_readme_carries_the_expected_install_line(self):
        assert EXPECTED_INSTALL in _read(README), f"README must carry `{EXPECTED_INSTALL}`"

    def test_action_example_carries_it_too(self):
        """The workflow example is executed, not read -- it must not 404."""
        action_example = [
            line for line in _read(README).splitlines() if line.strip().startswith("- run: pip")
        ]
        assert action_example, "expected a `run: pip install` step in the README Actions example"
        assert EXPECTED_INSTALL in "\n".join(action_example), (
            f"the GitHub Actions example installs something other than "
            f"`{EXPECTED_INSTALL}`; this line actually executes on every run"
        )


class TestNoBarePyPIInstallAnywhere:
    def test_surfaces_were_found(self):
        """Guard the guard: an empty surface list would assert nothing."""
        found = doc_surfaces()
        assert found, f"none of {DOC_SURFACES} exists -- the surface list is stale"
        assert "README.md" in [name for name, _ in found]

    def test_no_surface_installs_a_forbidden_bare_name(self):
        offenders = {
            name: lines[:5] for name, path in doc_surfaces() if (lines := bare_install_lines(_read(path)))
        }
        offenders = {name: lines for name, lines in offenders.items() if lines}
        assert not offenders, (
            f"these files tell readers to `pip install` {sorted(FORBIDDEN_TARGETS)}, which on "
            f"PyPI is not this project. Use `{EXPECTED_INSTALL}`. "
            f"Offending files and lines: {offenders}"
        )


class TestTargetParsing:
    """Literal inputs, so editing a constant above cannot make these pass."""

    def test_git_install_is_not_a_bare_name(self):
        line = "pip install git+https://github.com/yunaremaia/vibeguard.git"
        assert install_targets(line) == []
        assert bare_install_lines(line) == []

    def test_short_name_is_a_bare_name(self):
        assert install_targets("pip install vibeguard") == ["vibeguard"]
        assert bare_install_lines("pip install vibeguard")

    def test_uv_and_pip3_variants_are_covered(self):
        for line in ("uv tool install vibeguard", "uv pip install vibeguard", "pip3 install vibeguard"):
            assert bare_install_lines(line), line

    def test_unrelated_packages_are_not_caught(self):
        for line in (
            "pip install pre-commit",
            "python -m pip install --upgrade pip",
            "python -m pip install ruff",
            "python -m pip install build twine",
        ):
            assert install_targets(line) and not bare_install_lines(line), line

    def test_from_source_blocks_are_not_caught(self):
        """`git clone` + `pip install -e .` is a legitimate install, not a lie."""
        for line in (
            "pip install -e .",
            'pip install -e ".[dev]"',
            "pip install -r requirements.txt",
            "RUN pip install --no-cache-dir .",
        ):
            assert not bare_install_lines(line), line

    def test_bare_d_distribution_name_is_forbidden_while_unpublished(self):
        """`-py` is still a bare install target, and it still 404s."""
        assert install_targets("pip install vibeguard-py") == ["vibeguard-py"]
        assert bare_install_lines("pip install vibeguard-py") == (["pip install vibeguard-py"] if not PUBLISHED else [])


class TestTheRegexIsNotANaiveSubstringCheck:
    def test_a_substring_check_could_not_separate_the_two_names(self):
        """Documents the trap this guard exists to avoid."""
        assert "pip install vibeguard" in "pip install vibeguard-py"

    def test_the_requirement_parser_does_separate_them(self):
        assert _requirement_name("vibeguard-py") == "vibeguard-py"
        assert _requirement_name("vibeguard") == "vibeguard"
        assert _requirement_name("git+https://github.com/yunaremaia/vibeguard.git") is None


class TestReadmeDisclosesTheNameSituation:
    """A reader who sees `vibeguard-py` deserves to know what is going on."""

    def test_short_name_is_disclosed_as_foreign(self):
        text = _read(README).lower()
        assert FOREIGN_NAME in text
        assert "pypi" in text
        assert any(
            phrase in text for phrase in ("different author", "another author", "unrelated")
        ), "README must say the short PyPI name belongs to another project"

    def test_unpublished_state_is_disclosed(self):
        """Otherwise a git URL in the install block reads as a mistake."""
        text = _read(README).lower()
        assert any(
            phrase in text for phrase in ("not published", "not yet on pypi", "not yet published")
        ), "README must state the project is not on PyPI yet, so the git URL is expected"


class TestReadmeCliExamples:
    """The README must document invocations the CLI actually accepts.

    The CLI takes the target as a bare positional argument -- there is no
    `scan` subcommand. A `vibeguard scan .` example looks plausible but exits 2
    with "unrecognized arguments", so it is checked against the real parser.
    """

    def test_no_nonexistent_scan_subcommand(self):
        offenders = [
            line.strip()
            for line in _read(README).splitlines()
            if re.search(rf"\b{REPO_NAME}\s+scan\b", line)
        ]
        assert not offenders, (
            f"`{REPO_NAME}` has no `scan` subcommand; the target is positional "
            f"(`{REPO_NAME} .`). Found: {offenders}"
        )

    def test_documented_invocations_parse(self):
        from vibeguard.cli import build_parser

        parser = build_parser()
        examples = re.findall(rf"^\s*(?:\$ )?({REPO_NAME} [^\n|`]+)", _read(README), re.M)
        assert examples, "expected CLI examples in the README"
        for example in examples:
            parser.parse_args(shlex.split(example)[1:])  # SystemExit on an invalid example


class TestConsoleScriptIsUnchanged:
    def test_script_name_matches_the_repo_name(self):
        assert list(_PYPROJECT["project"]["scripts"]) == [REPO_NAME], (
            "only the distribution name carries the `-py` suffix; the console "
            "script keeps the repo name"
        )
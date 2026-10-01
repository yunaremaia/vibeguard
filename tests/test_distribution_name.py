"""Regression guard: the README must never send users to someone else's package.

``vibeguard`` is the repo name, the CLI command and the importable module, but
it is **not** the PyPI distribution name: the short ``vibeguard`` project on
PyPI belongs to an unrelated project by a different author. A README that says
``pip install vibeguard`` therefore installs a stranger's code, silently.

CI cannot catch this on its own -- CI installs from source with
``pip install -e .``, so the published name is never exercised. These tests pin
the README to the ``[project] name`` declared in ``pyproject.toml`` and assert
the name conflict is disclosed, so the next rename cannot silently regress.
"""

import re
import shlex
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
README = REPO_ROOT / "README.md"

# The authoritative PyPI distribution name, read rather than hardcoded so this
# test keeps working across future renames.
DIST_NAME = re.search(
    r'^name\s*=\s*"([^"]+)"', (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M
).group(1)

# The short name that collides with the other author's project.
SHORT_NAME = DIST_NAME.removesuffix("-py")

# `pip install <name>`, optionally quoted.
#
# The negative lookahead is load-bearing: `pip install vibeguard-py` is a
# substring of nothing dangerous, but a naive substring check for
# "pip install vibeguard" also matches "pip install vibeguard-py" and would
# fail the very line this test exists to protect. `(?![\w-])` stops the match
# only when the bare name really is the whole package token.
PIP_INSTALL = re.compile(
    r"""pip install ["']?(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)(?![\w-])"""
)


def bare_install_lines(text: str) -> list[str]:
    """Return the ``pip install <name>`` lines in *text* that use the short name."""
    return [
        line.strip()
        for line in text.splitlines()
        if PIP_INSTALL.search(line) and PIP_INSTALL.search(line).group("name") == SHORT_NAME
    ]


class TestReadmeDistributionName:
    def test_readme_installs_the_declared_distribution(self):
        """The install instructions name the distribution pyproject declares."""
        assert f"pip install {DIST_NAME}" in README.read_text(encoding="utf-8"), (
            f"README must tell users `pip install {DIST_NAME}`, the name in pyproject.toml"
        )

    def test_readme_never_installs_the_colliding_short_name(self):
        """`pip install vibeguard` installs another author's project."""
        offenders = bare_install_lines(README.read_text(encoding="utf-8"))
        assert not offenders, (
            f"`pip install {SHORT_NAME}` resolves to a different author's project on PyPI. "
            f"Install {DIST_NAME!r} instead. Found: {offenders}"
        )

    def test_readme_discloses_the_name_conflict(self):
        """The name collision is stated, so the odd distribution name is not a mystery."""
        text = README.read_text(encoding="utf-8").lower()
        assert SHORT_NAME in text
        assert "pypi" in text
        assert any(
            phrase in text for phrase in ("different author", "another author", "unrelated")
        ), "README must say the short PyPI name belongs to a different project/author"

    def test_install_line_matches_pyproject_name(self):
        """The name on the install line is exactly the pyproject name (no typos)."""
        names = {
            m.group("name")
            for m in PIP_INSTALL.finditer(README.read_text(encoding="utf-8"))
            # `pip install --upgrade pip` and friends are not this project.
            if m.group("name") not in {"pip", "-e", "ruff", "build", "twine", "pytest"}
        }
        assert DIST_NAME in names, f"README installs {sorted(names)}, expected {DIST_NAME!r}"
        assert SHORT_NAME not in names


class TestNegativeLookaheadIsNotNaive:
    """The regex must distinguish ``vibeguard-py`` from ``vibeguard``."""

    def test_suffixed_name_is_accepted(self):
        assert not bare_install_lines(f"pip install {DIST_NAME}"), (
            "the suffixed distribution name must pass the bare-name check"
        )

    def test_bare_name_is_rejected(self):
        assert bare_install_lines(f"pip install {SHORT_NAME}")

    def test_naive_substring_search_would_be_wrong(self):
        """Documents why a plain substring check cannot be used here."""
        needle = f"pip install {SHORT_NAME}"
        assert needle in f"pip install {DIST_NAME}", (
            "substring search is ambiguous by construction; the regex must carry this"
        )


class TestReadmeCliExamples:
    """The README must document invocations the CLI actually accepts.

    The CLI takes the target as a bare positional argument -- there is no
    `scan` subcommand. A `vibeguard scan .` example looks plausible but exits 2
    with "unrecognized arguments", so it is checked against the real parser.
    """

    def test_no_nonexistent_scan_subcommand(self):
        offenders = [
            line.strip()
            for line in README.read_text(encoding="utf-8").splitlines()
            if re.search(rf"\b{SHORT_NAME}\s+scan\b", line)
        ]
        assert not offenders, (
            f"`{SHORT_NAME}` has no `scan` subcommand; the target is positional "
            f"(`{SHORT_NAME} .`). Found: {offenders}"
        )

    def test_documented_invocations_parse(self):
        """Every `vibeguard ...` example in the README parses with the real CLI."""
        from vibeguard.cli import build_parser

        parser = build_parser()
        examples = re.findall(rf"^\s*(?:\$ )?({SHORT_NAME} [^\n|`]+)", README.read_text(encoding="utf-8"), re.M)
        assert examples, "expected CLI examples in the README"
        for example in examples:
            argv = shlex.split(example)
            parser.parse_args(argv[1:])  # raises SystemExit on an invalid example
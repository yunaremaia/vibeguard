"""Shared fixtures for the VibeGuard test suite.

Every fixture builds real files on disk, so the tests exercise the public
behaviour of the package rather than mocking it away.
"""

from pathlib import Path

import pytest

# A file that trips one rule of each severity the scanner can emit:
# VGB-001 (CRITICAL, hardcoded key), VGB-004/006 (HIGH, CORS + missing auth)
# and VGB-005 (MEDIUM, debug mode).
VULNERABLE_PY_SOURCE = """\
import os

API_KEY = "REDACTEDFAKEKEYDONTUSE0000"
DEBUG = True


@app.get("/admin/users")
def list_users():
    uid = request.args.get("id")
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
    return eval(request.args.get("expr", "1"))
"""

CLEAN_SOURCE = """\
def add(a, b):
    return a + b
"""


@pytest.fixture
def clean_file(tmp_path: Path) -> Path:
    """A supported-extension file with nothing worth reporting."""
    path = tmp_path / "clean.py"
    path.write_text(CLEAN_SOURCE, encoding="utf-8")
    return path


@pytest.fixture
def vulnerable_file(tmp_path: Path) -> Path:
    """A Python file that triggers several rules."""
    path = tmp_path / "vulnerable.py"
    path.write_text(VULNERABLE_PY_SOURCE, encoding="utf-8")
    return path

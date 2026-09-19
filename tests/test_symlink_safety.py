"""Tests for symlink path traversal protection."""
import sys
from pathlib import Path

sys.path.insert(0, "src")

from vibeguard.scanner import scan_directory
from vibeguard.models import ScanResult


def test_symlink_outside_target_is_skipped(tmp_path):
    """A symlink pointing outside the target must be skipped."""
    safe = tmp_path / "safe_project"
    safe.mkdir()
    target_file = safe / "app.py"
    target_file.write_text("print('ok')\n")

    outside = tmp_path / "outside"
    outside.mkdir()
    outside_file = outside / "secret.py"
    outside_file.write_text("print('secret')\n")

    link = safe / "link.py"
    link.symlink_to(outside_file)

    result = scan_directory(safe)
    assert result.files_scanned == 1, "only the safe file should be scanned"


def test_symlink_inside_target_is_scanned(tmp_path):
    """A symlink pointing within the target must be scanned."""
    project = tmp_path / "project"
    project.mkdir()
    original = project / "module.py"
    original.write_text("print('hello')\n")

    link = project / "alias.py"
    link.symlink_to(original)

    result = scan_directory(project)
    assert result.files_scanned == 2


def test_broken_symlink_does_not_crash(tmp_path):
    """Broken symlink must be skipped without error."""
    project = tmp_path / "project"
    project.mkdir()
    (project / "good.py").write_text("print('ok')\n")
    (project / "broken.py").symlink_to(project / "nonexistent.py")

    result = scan_directory(project)
    assert result.files_scanned == 1

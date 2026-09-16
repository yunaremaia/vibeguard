
from vibeguard import __version__
from vibeguard.cli import main
import sys

def test_version_constant():
    assert __version__

def test_version_flag(capsys):
    try:
        sys.argv = ["vibeguard", "--version"]
        main()
    except SystemExit as e:
        assert e.code == 0
    out = capsys.readouterr().out
    assert __version__ in out

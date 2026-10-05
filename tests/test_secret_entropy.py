"""Behavioural tests for VGB-040 (high-entropy hardcoded credentials).

Each case gets a positive, a negative that must stay silent, and a dedup case,
so a regression in any one of the three is visible in the name of the failure.
"""

from pathlib import Path

import pytest

from vibeguard.rules import secret_entropy
from vibeguard.rules.secret_entropy import RULE_ID, char_classes, shannon_entropy
from vibeguard.scanner import scan_file as scan_all_rules


def write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def rule_ids(findings) -> list[str]:
    return [f.rule_id for f in findings]


# ---------------------------------------------------------------------------
# Entropy scoring
# ---------------------------------------------------------------------------


def test_entropy_of_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_entropy_of_single_repeated_character_is_zero():
    assert shannon_entropy("aaaaaaaaaaaaaaaa") == 0.0


def test_entropy_of_random_string_exceeds_prose():
    assert shannon_entropy("xK9#mQ2$vB7!nR4@wZ8") > shannon_entropy("the quick brown fox")


def test_prose_scores_higher_entropy_than_random_hex():
    """Why entropy alone is not the gate: short-string entropy is biased high."""
    assert shannon_entropy("the quick brown fox jumps over") > shannon_entropy("7f3b9c1d2e4a5f6")


@pytest.mark.parametrize(
    "value,expected",
    [
        ("lowercase only here", 1),
        ("UPPERCASE1", 2),
        ("lowercase1", 2),
        ("lowerUPPER", 2),
        ("aB3$", 4),
        ("with space and 1 digit", 2),  # space is not a class
    ],
)
def test_char_classes_counts(value, expected):
    assert char_classes(value) == expected


# ---------------------------------------------------------------------------
# High-entropy credential assignments are flagged
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label,source",
    [
        ("aws_secret", 'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzAbc9"\n'),
        ("api_key", 'const apiKey = "7f3b9c1d2e4a5f6b8c0d1e2f3a4b5c6d";\n'),
        ("db_password", 'db_password: "Tr0ub4dor&3xKqz9Wv"\n'),
        ("auth_token", 'self.auth_token = "eyJhbGciOiJIUzI1NiJ9abcdEFG1234"\n'),
        ("signing_key", 'signing_key = "aB3$xY9!qL2#pR7@vN5&tW1*eJ6"\n'),
        ("quoted_pem_body", 'PRIVATE_KEY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"\n'),
    ],
)
def test_high_entropy_credential_is_flagged(tmp_path, label, source):
    findings = secret_entropy.scan_file(write(tmp_path, f"{label}.py", source))
    assert rule_ids(findings) == [RULE_ID], label
    assert findings[0].severity == "CRITICAL"
    assert "bits/char" in findings[0].message
    assert "secrets manager" in findings[0].fix_hint


# ---------------------------------------------------------------------------
# Negatives: prose, placeholders, indirections, short values
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label,source",
    [
        ("plain_password", 'password = "Tr0ub4dor&3x"\n'),
        ("changelog_prose", 'token = "the quick brown fox jumps over"\n'),
        ("placeholder_changeme", 'api_key = "changeme-please-0000"\n'),
        ("placeholder_xxxx", 'api_key = "xxxxxxxxxxxxxxxxxxxx"\n'),
        ("env_indirection", 'api_key = os.environ["SERVICE_API_KEY"]\n'),
        ("template_indirection", 'api_key = "${SERVICE_API_KEY}"\n'),
        ("no_credential_name", 'colour = "#3f7b9c2a1e5d0b4"\n'),
        ("short_value", 'api_key = "abc123"\n'),
        ("low_entropy_padded", 'api_key = "aaaaaaaaaaaaaa1a"\n'),
        ("commented_out", '# api_key = "7f3b9c1d2e4a5f6b8c0d1e2f3a4b5c6d"\n'),
        ("js_comment", '// token = "7f3b9c1d2e4a5f6b8c0d1e2f3a4b5c6d"\n'),
        ("unquoted_value", "api_key = 7f3b9c1d2e4a5f6b8c0d1e2f3a4b5c6d\n"),
    ],
)
def test_non_secret_is_not_flagged(tmp_path, label, source):
    assert secret_entropy.scan_file(write(tmp_path, f"{label}.py", source)) == [], label


def test_clean_source_produces_no_findings(tmp_path):
    source = "def add(a, b):\n    return a + b\n"
    assert secret_entropy.scan_file(write(tmp_path, "clean.py", source)) == []


# ---------------------------------------------------------------------------
# One finding per line, even when several patterns land on the same line
# ---------------------------------------------------------------------------


def test_line_matching_assignment_twice_yields_one_finding(tmp_path):
    """A single credential line is reported once, not once per regex hit."""
    source = 'api_key = "7f3b9c1d2e4a5f6b8c0d1e2f3a4b5c6d"\n'
    findings = secret_entropy.scan_file(write(tmp_path, "dup.py", source))
    assert len(findings) == 1


def test_line_with_two_separate_credentials_reports_each_line(tmp_path):
    source = (
        'api_key = "7f3b9c1d2e4a5f6b8c0d1e2f3a4b5c6d"\n'
        'db_password = "Tr0ub4dor&3xKqz9Wv"\n'
    )
    findings = secret_entropy.scan_file(write(tmp_path, "two.py", source))
    assert [f.line for f in findings] == [1, 2]


# ---------------------------------------------------------------------------
# Location and snippet handling
# ---------------------------------------------------------------------------


def test_location_is_exact(tmp_path):
    source = "import os\n\nAPI_SECRET = 'aB3$xY9!qL2#pR7@vN5&tW1*eJ6'\n"
    findings = secret_entropy.scan_file(write(tmp_path, "loc.py", source))
    assert len(findings) == 1
    assert findings[0].line == 3
    assert findings[0].column == 1
    assert findings[0].snippet == "API_SECRET = 'aB3$xY9!qL2#pR7@vN5&tW1*eJ6'"


def test_long_snippet_is_truncated(tmp_path):
    value = "aB3$xY9!qL2#pR7@vN5&tW1*eJ6" * 6
    source = f'api_key = "{value}"\n'
    findings = secret_entropy.scan_file(write(tmp_path, "long.py", source))
    assert findings[0].snippet.endswith("...")
    assert len(findings[0].snippet) == 123


def test_secret_pushed_past_the_line_length_limit_is_not_matched(tmp_path):
    """The truncation guard drops a match that only exists beyond the cap."""
    prefix = "x" * (secret_entropy.MAX_LINE_LENGTH + 10)
    source = f'{prefix} api_key = "aB3$xY9!qL2#pR7@vN5&tW1*eJ6"\n'
    assert secret_entropy.scan_file(write(tmp_path, "huge.py", source)) == []


def test_secret_on_the_same_line_after_the_limit_is_still_found(tmp_path):
    """Truncation is a ReDoS guard, not a filter: the head of the line is kept."""
    prefix = "#" + "y" * (secret_entropy.MAX_LINE_LENGTH + 50)
    source = f'{prefix}\napi_key = "aB3$xY9!qL2#pR7@vN5&tW1*eJ6"\n'
    findings = secret_entropy.scan_file(write(tmp_path, "mixed.py", source))
    assert [f.line for f in findings] == [2]


# ---------------------------------------------------------------------------
# Robustness and registry wiring
# ---------------------------------------------------------------------------


def test_missing_file_yields_no_findings(tmp_path):
    assert secret_entropy.scan_file(tmp_path / "gone.py") == []


def test_unreadable_file_yields_no_findings(tmp_path, monkeypatch):
    path = write(tmp_path, "boom.py", 'api_key = "aB3$xY9!qL2#pR7@vN5&tW1*eJ6"\n')

    def explode(*_args, **_kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr(Path, "read_text", explode)
    assert secret_entropy.scan_file(path) == []


def test_rule_is_reachable_through_the_scanner(tmp_path):
    path = write(tmp_path, "wired.py", 'api_key = "aB3$xY9!qL2#pR7@vN5&tW1*eJ6"\n')
    assert RULE_ID in rule_ids(scan_all_rules(path))

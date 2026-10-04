"""Behavioural tests for the individual detection rules.

The rules are the product, so these assert on the *rule id*, *severity* and
*location* a real file produces — plus the false-positive guards (comment
skipping, lock files) that keep the scanner usable.
"""

from pathlib import Path

import pytest

from vibeguard.rules import cors_debug, dangerous_functions, missing_auth, secrets, sql_injection


def write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def rule_ids(findings) -> list[str]:
    return [f.rule_id for f in findings]


# ---------------------------------------------------------------------------
# VGB-001 — hardcoded secrets
# ---------------------------------------------------------------------------


def test_secrets_detects_hardcoded_api_key(tmp_path):
    """A quoted 20+ char key after api_key= is reported as CRITICAL."""
    path = write(tmp_path, "conf.py", 'API_KEY = "abcdefghij0123456789ABCDEF"\n')
    findings = secrets.scan_file(path)
    assert rule_ids(findings) == ["VGB-001"]
    assert findings[0].severity == "CRITICAL"
    assert findings[0].line == 1
    assert findings[0].column == 1
    assert findings[0].snippet.startswith("API_KEY =")
    assert "secrets manager" in findings[0].fix_hint


@pytest.mark.parametrize(
    ("label", "source"),
    [
        ("aws", 'KEY = "AKIAIOSFODNN7EXAMPLE"\n'),
        ("generic_token", 'password = "hunter2hunter2"\n'),
        ("private_key", "-----BEGIN RSA PRIVATE KEY-----\n"),
        ("github", 'TOKEN = "ghp_' + "a" * 36 + '"\n'),
        ("slack", 'SLACK = "xoxb-1234567890abcdef"\n'),
    ],
)
def test_secrets_detects_each_secret_family(tmp_path, label, source):
    """Every secret family in the rule has at least one triggering sample."""
    path = write(tmp_path, f"{label}.py", source)
    assert "VGB-001" in rule_ids(secrets.scan_file(path)), label


def test_secrets_ignores_lockfiles(tmp_path):
    """Lock files are pure false-positive sources, so they are skipped."""
    path = write(tmp_path, "package-lock.json", 'API_KEY = "abcdefghij0123456789ABCDEF"\n')
    assert secrets.scan_file(path) == []


def test_secrets_ignores_commented_lines(tmp_path):
    """A commented-out secret is documentation, not a live credential."""
    path = write(tmp_path, "app.py", '# API_KEY = "abcdefghij0123456789ABCDEF"\n')
    assert secrets.scan_file(path) == []


def test_secrets_truncates_long_snippet_in_output(tmp_path):
    """Reported snippets are capped so a huge line cannot flood the report."""
    padding = "x" * 200
    path = write(tmp_path, "app.py", f'API_KEY = "abcdefghij0123456789ABCDEF"  # {padding}\n')
    snippet = secrets.scan_file(path)[0].snippet
    assert len(snippet) == 123
    assert snippet.endswith("...")


def test_secrets_reports_line_number_of_offending_line(tmp_path):
    """The reported line number points at the secret, not the file start."""
    path = write(tmp_path, "app.py", "import os\n\n\nAPI_KEY = \"abcdefghij0123456789ABCDEF\"\n")
    assert secrets.scan_file(path)[0].line == 4


def test_generic_token_pattern_matches_a_real_credential(tmp_path):
    """Regression: the token/password pattern must match quoted literals.

    Its character class originally placed "/" *outside* the class, so it
    compiled to "quote, one char, 8+ slashes, quote" and could never fire.
    This asserts the rule detects the credentials it advertises.
    """
    path = write(tmp_path, "conf.py", 'password = "correct-horse-battery"\n')
    findings = secrets.scan_file(path)
    assert [f.message for f in findings] == ["Hardcoded secret/token detected"]
    assert findings[0].column == 1


def test_generic_token_pattern_requires_eight_characters(tmp_path):
    """The 8-character minimum keeps short values from being flagged."""
    path = write(tmp_path, "conf.py", 'password = "short"\n')
    assert secrets.scan_file(path) == []


def test_generic_token_pattern_ignores_urls_and_placeholders(tmp_path):
    """Values containing slashes/braces are config, not credentials."""
    for value in ('"https://example.com/a/b"', '"{}"', '"{user_id}"'):
        path = write(tmp_path, "conf.py", f"password = {value}\n")
        assert secrets.scan_file(path) == [], value


# ---------------------------------------------------------------------------
# VGB-002 — SQL injection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "source"),
    [
        ("fstring", 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n'),
        ("format", 'cursor.execute("SELECT * FROM users WHERE id = {}".format(uid))\n'),
        ("percent", 'cursor.execute("SELECT * FROM users WHERE id = %s" % uid)\n'),
        ("concat", 'cursor.execute("SELECT * FROM users WHERE id = " + uid)\n'),
        ("template_literal", "db.query(`SELECT * FROM users WHERE id = ${id}`)\n"),
    ],
)
def test_sql_injection_detects_each_formatting_style(tmp_path, label, source):
    """All five SQL formatting styles are flagged as CRITICAL."""
    path = write(tmp_path, f"{label}.py", source)
    findings = sql_injection.scan_file(path)
    assert "VGB-002" in rule_ids(findings), label
    assert all(f.severity == "CRITICAL" for f in findings if f.rule_id == "VGB-002")
    assert "parameterized" in findings[0].fix_hint


def test_sql_injection_ignores_parameterized_queries(tmp_path):
    """The safe idiom must not be reported."""
    path = write(tmp_path, "safe.py", "cursor.execute('SELECT * FROM users WHERE id = ?', (uid,))\n")
    assert sql_injection.scan_file(path) == []


def test_sql_injection_ignores_commented_lines(tmp_path):
    """A commented-out query is not a live vulnerability."""
    path = write(tmp_path, "app.py", '# cursor.execute(f"SELECT * FROM t WHERE id = {uid}")\n')
    assert sql_injection.scan_file(path) == []


def test_sql_injection_truncates_long_snippet_in_output(tmp_path):
    """Reported snippets are capped so a huge line cannot flood the report."""
    # S608 is expected here: an f-string SQL query is the exact input this
    # rule must detect, so the string is fixture data, not a real query.
    path = write(
        tmp_path,
        "app.py",
        f'cursor.execute(f"SELECT * FROM t WHERE id = {{uid}}")  # {"x" * 200}\n',  # noqa: S608
    )
    snippet = sql_injection.scan_file(path)[0].snippet
    assert len(snippet) == 123
    assert snippet.endswith("...")


# ---------------------------------------------------------------------------
# VGB-003 — dangerous functions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "source"),
    [
        ("python_eval", "result = eval(request.args['x'])\n"),
        ("python_exec", "exec(params)\n"),
        ("os_system", "os.system(body)\n"),
        ("shell_true", "subprocess.run(cmd, shell=True)\n"),
        ("js_eval", "const out = eval(req.query.expr);\n"),
        ("js_function", "const fn = new Function(user);\n"),
        ("go_exec", 'exec.Command("sh", fmt.Sprintf("-c %s", input))\n'),
    ],
)
def test_dangerous_functions_detects_each_pattern(tmp_path, label, source):
    """Every dangerous-function pattern has a triggering sample."""
    path = write(tmp_path, f"{label}.py", source)
    findings = dangerous_functions.scan_file(path)
    assert "VGB-003" in rule_ids(findings), label
    assert findings[0].severity == "CRITICAL"


def test_dangerous_functions_ignores_literal_eval(tmp_path):
    """eval() on a literal is not user-input-driven code execution."""
    path = write(tmp_path, "safe.py", "value = eval('1 + 1')\n")
    assert dangerous_functions.scan_file(path) == []


def test_dangerous_functions_ignores_commented_lines(tmp_path):
    """A commented-out eval is documentation, not a vulnerability."""
    path = write(tmp_path, "app.py", "# result = eval(request.args['x'])\n")
    assert dangerous_functions.scan_file(path) == []


def test_dangerous_functions_truncates_long_snippet_in_output(tmp_path):
    """Reported snippets are capped so one huge line cannot flood the report."""
    path = write(tmp_path, "app.py", f"result = eval(request.args['x'])  # {'x' * 200}\n")
    snippet = dangerous_functions.scan_file(path)[0].snippet
    assert len(snippet) == 123
    assert snippet.endswith("...")


# ---------------------------------------------------------------------------
# MAX_LINE_LENGTH guard (ReDoS protection)
# ---------------------------------------------------------------------------


def _past_limit_line(payload: str, limit: int) -> str:
    """A single line where *payload* only starts after the truncation point."""
    return "x" * (limit + 10) + payload


def test_secrets_ignores_secrets_past_the_line_length_limit(tmp_path):
    """Content beyond MAX_LINE_LENGTH is truncated away before matching."""
    limit = secrets.MAX_LINE_LENGTH
    source = _past_limit_line('API_KEY = "abcdefghij0123456789ABCDEF"', limit)
    assert len(source) > limit
    assert secrets.scan_file(write(tmp_path, "minified.py", source + "\n")) == []


def test_sql_injection_ignores_queries_past_the_line_length_limit(tmp_path):
    """The same guard protects the SQL rule from catastrophic backtracking."""
    source = _past_limit_line('cursor.execute(f"SELECT * FROM t WHERE id = {uid}")', sql_injection.MAX_LINE_LENGTH)
    assert sql_injection.scan_file(write(tmp_path, "minified.py", source + "\n")) == []


def test_dangerous_functions_ignores_calls_past_the_line_length_limit(tmp_path):
    """...and the dangerous-function rule."""
    source = _past_limit_line("result = eval(request.args['x'])", dangerous_functions.MAX_LINE_LENGTH)
    assert dangerous_functions.scan_file(write(tmp_path, "minified.py", source + "\n")) == []


def test_rules_still_match_within_the_line_length_limit(tmp_path):
    """The guard must not suppress a secret that starts early in a long line."""
    tail = "#" + "y" * (secrets.MAX_LINE_LENGTH + 50)
    source = f'API_KEY = "abcdefghij0123456789ABCDEF"  {tail}'
    findings = secrets.scan_file(write(tmp_path, "long.py", source + "\n"))
    assert [f.rule_id for f in findings] == ["VGB-001"]


# ---------------------------------------------------------------------------
# VGB-004 / VGB-005 — CORS and debug
# ---------------------------------------------------------------------------


def test_cors_wildcard_is_high_severity(tmp_path):
    """A wildcard origin is a HIGH finding with a CORS-specific fix hint."""
    path = write(tmp_path, "app.py", 'CORS(app, origins="*")\n')
    findings = cors_debug.scan_file(path)
    assert "VGB-004" in rule_ids(findings)
    finding = next(f for f in findings if f.rule_id == "VGB-004")
    assert finding.severity == "HIGH"
    assert "trusted domains" in finding.fix_hint


def test_cors_ignores_specific_origins(tmp_path):
    """An explicit origin allowlist must not be flagged."""
    path = write(tmp_path, "app.py", 'CORS(app, origins=["https://app.example.com"])\n')
    assert "VGB-004" not in rule_ids(cors_debug.scan_file(path))


def test_debug_true_is_medium_severity(tmp_path):
    """DEBUG = True in production code is a MEDIUM finding."""
    path = write(tmp_path, "settings.py", "DEBUG = True\n")
    findings = cors_debug.scan_file(path)
    assert "VGB-005" in rule_ids(findings)
    finding = next(f for f in findings if f.rule_id == "VGB-005")
    assert finding.severity == "MEDIUM"
    assert "DEBUG=False" in finding.fix_hint


def test_debug_false_is_not_reported(tmp_path):
    """The safe configuration produces no finding."""
    path = write(tmp_path, "settings.py", "DEBUG = False\n")
    assert "VGB-005" not in rule_ids(cors_debug.scan_file(path))


def test_cors_and_debug_rules_ignore_commented_lines(tmp_path):
    """Commented configuration is documentation, not live config."""
    path = write(tmp_path, "app.py", '# CORS(app, origins="*")\n// DEBUG = True\n')
    assert cors_debug.scan_file(path) == []


def test_cors_and_debug_truncate_long_snippets_in_output(tmp_path):
    """Both severities cap the reported snippet so the report stays readable."""
    padding = "#" + "x" * 200
    path = write(tmp_path, "app.py", f'CORS(app, origins="*")  {padding}\nDEBUG = True  {padding}\n')
    findings = cors_debug.scan_file(path)
    by_rule = {f.rule_id: f for f in findings}
    for rule_id in ("VGB-004", "VGB-005"):
        assert by_rule[rule_id].snippet.endswith("...")
        assert by_rule[rule_id].snippet.startswith(("CORS", "DEBUG"))


# ---------------------------------------------------------------------------
# VGB-006 — missing authentication
# ---------------------------------------------------------------------------


def test_endpoint_without_auth_is_reported(tmp_path):
    """A protected-looking route with no auth anywhere in the file is flagged."""
    path = write(tmp_path, "app.py", '@app.get("/admin/users")\ndef list_users():\n    pass\n')
    findings = missing_auth.scan_file(path)
    assert "VGB-006" in rule_ids(findings)
    finding = next(f for f in findings if f.rule_id == "VGB-006")
    assert finding.severity == "HIGH"
    assert finding.line == 1
    assert "login_required" in finding.fix_hint


def test_endpoint_carrying_an_auth_decorator_is_not_reported(tmp_path):
    """Auth guarding *this* route suppresses the finding for it."""
    path = write(
        tmp_path,
        "app.py",
        '@app.get("/admin/users")\n@login_required\ndef list_users():\n    pass\n',
    )
    assert missing_auth.scan_file(path) == []


def test_unprotected_endpoint_is_reported_despite_auth_elsewhere_in_the_file(tmp_path):
    """Regression #130: an incidental `import jwt` silences every route in the file.

    A bare module import guards nothing, so the rule must still fire.
    """
    path = write(
        tmp_path,
        "api.py",
        "import jwt\n\n\n@app.get('/admin/users')\ndef list_users():\n    return []\n",
    )
    assert "VGB-006" in rule_ids(missing_auth.scan_file(path))


def test_auth_on_one_route_does_not_excuse_the_next(tmp_path):
    """Suppression is per endpoint: the unprotected neighbour is still reported."""
    path = write(
        tmp_path,
        "app.py",
        "@app.get('/admin/users')\n"
        "@login_required\n"
        "def list_users():\n"
        "    return []\n"
        "\n"
        "\n"
        "@app.get('/admin/wipe')\n"
        "def wipe():\n"
        "    return None\n",
    )
    findings = missing_auth.scan_file(path)
    # set(), not list(): a route matching several ENDPOINT_PATTERNS already emits
    # one finding per pattern (pre-existing, unrelated to the suppression scope).
    assert {f.line for f in findings} == {7}


def test_route_signed_with_depends_is_not_reported(tmp_path):
    """FastAPI guards the endpoint through its own signature."""
    path = write(
        tmp_path,
        "app.py",
        "@app.get('/admin/users')\n"
        "def list_users(user=Depends(get_current_user)):\n"
        "    return []\n",
    )
    assert missing_auth.scan_file(path) == []


def test_public_endpoints_are_exempt(tmp_path):
    """Health/status/login routes are public by design."""
    for route in ("/health", "/ping", "/status", "/docs", "/login"):
        path = write(tmp_path, "app.py", f'@app.get("{route}")\ndef check():\n    pass\n')
        assert missing_auth.scan_file(path) == [], route


def test_missing_auth_ignores_commented_endpoints(tmp_path):
    """A commented-out route is not a live endpoint."""
    path = write(tmp_path, "app.py", '# @app.get("/admin/users")\n')
    assert missing_auth.scan_file(path) == []


def test_missing_auth_truncates_long_snippet_in_output(tmp_path):
    """Reported snippets are capped so a huge line cannot flood the report."""
    path = write(tmp_path, "app.py", f'@app.get("/admin/users")  # {"x" * 200}\n')
    snippet = next(f for f in missing_auth.scan_file(path) if f.rule_id == "VGB-006").snippet
    assert len(snippet) == 123
    assert snippet.endswith("...")
